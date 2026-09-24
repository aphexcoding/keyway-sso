<?php

declare(strict_types=1);

use Keyway\Sso\Core\Attribute\AttributeMap;
use Keyway\Sso\Core\Attribute\AttributeMapper;
use Keyway\Sso\Core\Attribute\AttributeRule;
use Keyway\Sso\Core\Attribute\UserField;
use Keyway\Sso\Core\Diagnostics\DiagnosticEvent;
use Keyway\Sso\Core\Diagnostics\DiagnosticsRecorder;
use Keyway\Sso\Core\Diagnostics\LoginOutcome;
use Keyway\Sso\Core\Diagnostics\Masker;
use Keyway\Sso\Core\Group\AdminRule;
use Keyway\Sso\Core\Group\GroupMap;
use Keyway\Sso\Core\Group\GroupMapper;
use Keyway\Sso\Core\Group\GroupRule;
use Keyway\Sso\Core\Group\GroupSyncMode;
use Keyway\Sso\Core\Identity\IdentityPayload;
use Keyway\Sso\Core\Provisioning\ProvisioningPolicy;
use Keyway\Sso\Core\Provisioning\ProvisioningSettings;
use Keyway\Sso\Core\Provisioning\UserMatchKey;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\Test\Support\CollectingSink;
use Keyway\Sso\Test\Support\FixedClock;
use Keyway\Sso\Test\Support\SequenceRandomSource;

$recorder = static function (CollectingSink $sink): DiagnosticsRecorder {
    return new DiagnosticsRecorder($sink, new FixedClock(1_700_000_000), new SequenceRandomSource());
};

return [
    'values are masked but remain recognisable' => static function (): void {
        Assert::same('j***n@example.com', Masker::maskValue('jan.kowalskin@example.com'));
        Assert::same('***@example.com', Masker::maskValue('ja@example.com'));
        Assert::same('***', Masker::maskValue('abcd'));
        Assert::same('ab***yz', Masker::maskValue('abcdefghijklmnoxyz'));
        Assert::same('', Masker::maskValue('   '));
        Assert::same('***', Masker::maskValue('@example.com'));
    },

    'credential-looking claim names are redacted whole' => static function (): void {
        foreach ([
            'password',
            'SAMLResponse',
            'id_token',
            'access_token',
            'clientSecret',
            'x509Certificate',
            'Authorization',
            'authorization_code',
            'userAssertion',
        ] as $name) {
            Assert::true(Masker::isSensitiveName($name), $name);
        }

        foreach (['email', 'givenName', 'memberOf', 'department', 'employeeId'] as $name) {
            Assert::false(Masker::isSensitiveName($name), $name);
        }
    },

    'attribute masking redacts, truncates and caps' => static function (): void {
        $masked = Masker::maskAttributes([
            'email' => ['jan.kowalski@example.com'],
            'SAMLResponse' => ['PHNhbWxwOlJlc3BvbnNlIHZlcnNpb249IjIuMCI+'],
            'roles' => ['a1111', 'b2222', 'c3333', 'd4444', 'e5555', 'f6666', 'g7777'],
        ], 30, 5);

        Assert::same([Masker::REDACTED], $masked['SAMLResponse']);
        Assert::same('j***i@example.com', $masked['email'][0]);
        Assert::same(6, count($masked['roles']));
        Assert::same('[+2 more]', $masked['roles'][5]);
    },

    'too many attributes are cut off with a marker' => static function (): void {
        $attributes = [];
        for ($i = 0; $i < 40; $i++) {
            $attributes['claim' . $i] = ['value' . $i];
        }

        $masked = Masker::maskAttributes($attributes, 5, 5);

        Assert::same(6, count($masked));
        Assert::true(isset($masked[Masker::TRUNCATED]));
        Assert::same('35 more attribute(s)', $masked[Masker::TRUNCATED][0]);
    },

    'group names are shown in full because that is what is debugged' => static function (): void {
        $groups = Masker::groupList(['CN=Editors,OU=Groups,DC=example,DC=com']);

        Assert::same('CN=Editors,OU=Groups,DC=example,DC=com', $groups[0]);
    },

    'a successful login is recorded with its mapping' => static function () use ($recorder): void {
        $sink = new CollectingSink();
        $payload = new IdentityPayload(
            'jan@example.com',
            ['email' => 'jan@example.com', 'groups' => ['Editors']],
            'https://idp.example.com'
        );

        $attributes = (new AttributeMapper(new AttributeMap([
            AttributeRule::required('email', UserField::EMAIL),
        ])))->map($payload);

        $groups = (new GroupMapper(new GroupMap([GroupRule::exact('Editors', 'editors')])))
            ->map($payload);

        $decision = (new ProvisioningPolicy(new ProvisioningSettings()))
            ->decide($attributes, $groups, null);

        $event = $recorder($sink)->recordDecision('saml2', $payload, $decision);

        Assert::same(1, count($sink->events));
        Assert::same(LoginOutcome::Success, $event->outcome);
        Assert::true($event->isSuccess());
        Assert::same('saml2', $event->protocol);
        Assert::same(DiagnosticEvent::STAGE_PROVISIONING, $event->stage);
        Assert::same('https://idp.example.com', $event->issuer);
        Assert::same(1_700_000_000, $event->timestamp);
        Assert::same(['editors'], $event->mapping()['craftGroups']);
        Assert::same(true, $event->decision()['willCreateUser']);
        Assert::same(false, $event->decision()['grantsAdmin']);
    },

    'a denied login is recorded as denied, with the reason' => static function () use ($recorder): void {
        $sink = new CollectingSink();
        $payload = new IdentityPayload('jan@evil.com', ['email' => 'jan@evil.com']);

        $attributes = (new AttributeMapper(new AttributeMap([
            AttributeRule::required('email', UserField::EMAIL),
        ])))->map($payload);
        $groups = (new GroupMapper(new GroupMap()))->map($payload);

        $decision = (new ProvisioningPolicy(new ProvisioningSettings(
            true,
            true,
            false,
            UserMatchKey::Email,
            ['example.com']
        )))->decide($attributes, $groups, null);

        $event = $recorder($sink)->recordDecision('saml2', $payload, $decision);

        Assert::same(LoginOutcome::Denied, $event->outcome);
        Assert::same('domain_not_allowed', $event->reasonCode);
        Assert::false($event->isSuccess());
        Assert::contains('allowed list', $event->message);
    },

    'an admin grant is visible in the record' => static function () use ($recorder): void {
        $sink = new CollectingSink();
        $payload = new IdentityPayload('jan@example.com', [
            'email' => 'jan@example.com',
            'groups' => ['Craft-Admins'],
        ]);

        $attributes = (new AttributeMapper(new AttributeMap([
            AttributeRule::required('email', UserField::EMAIL),
        ])))->map($payload);

        $groups = (new GroupMapper(new GroupMap(
            [],
            [AdminRule::exact('Craft-Admins')],
            null,
            GroupSyncMode::Append,
            false,
            true
        )))->map($payload);

        $decision = (new ProvisioningPolicy(new ProvisioningSettings()))
            ->decide($attributes, $groups, null);

        $event = $recorder($sink)->recordDecision('saml2', $payload, $decision);

        Assert::same(true, $event->decision()['grantsAdmin']);
        Assert::same(true, $event->decision()['adminRuleMatched']);
    },

    'nothing replayable ends up in the stored row' => static function () use ($recorder): void {
        $sink = new CollectingSink();
        $secretAssertion = 'PHNhbWxwOlJlc3BvbnNlPjxTaWduYXR1cmU+U0VDUkVUPC9TaWduYXR1cmU+';
        $bearer = 'eyJhbGciOiJSUzI1NiJ9.SECRETPAYLOAD.SECRETSIG';

        $payload = new IdentityPayload('jan.kowalski@example.com', [
            'email' => 'jan.kowalski@example.com',
            'SAMLResponse' => $secretAssertion,
            'id_token' => $bearer,
            'sessionSecret' => 'hunter2hunter2',
        ], 'https://idp.example.com', 'session-index-123');

        $attributes = (new AttributeMapper(new AttributeMap([
            AttributeRule::required('email', UserField::EMAIL),
        ])))->map($payload);
        $groups = (new GroupMapper(new GroupMap()))->map($payload);
        $decision = (new ProvisioningPolicy(new ProvisioningSettings()))
            ->decide($attributes, $groups, null);

        $json = $recorder($sink)->recordDecision('saml2', $payload, $decision)->toJson();

        Assert::notContains($secretAssertion, $json);
        Assert::notContains($bearer, $json);
        Assert::notContains('hunter2hunter2', $json);
        Assert::notContains('jan.kowalski@example.com', $json);
        Assert::contains('@example.com', $json, 'the domain stays, it is what support needs');
        Assert::contains('SAMLResponse', $json, 'claim names stay, only values go');
        Assert::contains(Masker::REDACTED, $json);
    },

    'an event built without the recorder is masked all the same' => static function (): void {
        // The hole this closes: DiagnosticEvent has a public constructor, and the Craft layer
        // or a migration can build one directly. Before, whatever it passed went into the row
        // verbatim while the docblock promised otherwise.
        $assertion = 'PHNhbWxwOlJlc3BvbnNlPjxTaWduYXR1cmU+U0VDUkVUPC9TaWduYXR1cmU+';

        $event = new DiagnosticEvent(
            'abc123',
            1_700_000_000,
            'saml2',
            DiagnosticEvent::STAGE_PROTOCOL,
            LoginOutcome::Error,
            'signature_invalid',
            'Signature did not verify.',
            'https://idp.example.com',
            'jan.kowalski@example.com',
            ['email' => ['jan.kowalski@example.com'], 'SAMLResponse' => [$assertion]],
            ['rawAssertion' => $assertion, 'fields' => ['email' => 'j***i@example.com']],
            ['action' => 'deny', 'sessionToken' => 'hunter2hunter2']
        );

        $json = $event->toJson();

        Assert::same('j***i@example.com', $event->subject);
        Assert::same([Masker::REDACTED], $event->attributes()['SAMLResponse']);
        Assert::same(Masker::REDACTED, $event->mapping()['rawAssertion']);
        Assert::same(Masker::REDACTED, $event->decision()['sessionToken']);
        Assert::notContains($assertion, $json);
        Assert::notContains('hunter2hunter2', $json);
        Assert::notContains('jan.kowalski@example.com', $json);
        Assert::contains('@example.com', $json, 'the domain still helps support');
    },

    'the structural scrub bounds what a caller can stuff into a row' => static function (): void {
        $deep = ['a' => ['b' => ['c' => ['d' => ['e' => 'too deep']]]]];
        Assert::same(Masker::TRUNCATED, Masker::scrubStructure($deep)['a']['b']['c']['d']);

        $long = Masker::scrubStructure(['note' => str_repeat('x', 4000)]);
        Assert::same(256, strlen($long['note']));

        $wide = [];
        for ($i = 0; $i < 50; $i++) {
            $wide['k' . $i] = $i;
        }
        $scrubbed = Masker::scrubStructure($wide, 4, 10);
        Assert::same(11, count($scrubbed));
        Assert::same('40 more key(s)', $scrubbed[Masker::TRUNCATED]);

        Assert::same(
            ['flag' => true, 'count' => 3, 'nothing' => null],
            Masker::scrubStructure(['flag' => true, 'count' => 3, 'nothing' => null]),
            'scalars survive, the panel needs them'
        );
    },

    'an early failure is recorded without a payload' => static function () use ($recorder): void {
        $sink = new CollectingSink();

        $event = $recorder($sink)->recordFailure(
            'saml2',
            DiagnosticEvent::STAGE_PROTOCOL,
            'signature_invalid',
            'The assertion signature did not verify against the configured certificate.'
        );

        Assert::same(LoginOutcome::Error, $event->outcome);
        Assert::same(DiagnosticEvent::STAGE_PROTOCOL, $event->stage);
        Assert::same('', $event->issuer);
        Assert::same('', $event->subject);
        Assert::sameList([], $event->attributes());
        Assert::same(1, count($sink->events));
    },

    'a state failure keeps the payload masked' => static function () use ($recorder): void {
        $sink = new CollectingSink();
        $payload = new IdentityPayload('jan@example.com', ['email' => 'jan@example.com']);

        $event = $recorder($sink)->recordFailure(
            'oidc',
            DiagnosticEvent::STAGE_STATE,
            'already_used',
            'This login state has already been used.',
            $payload
        );

        Assert::same('j***n@example.com', $event->subject);
        Assert::notContains('jan@example.com', $event->toJson());
    },

    'events serialise to valid JSON even with multi-byte claims' => static function () use ($recorder): void {
        $sink = new CollectingSink();
        $payload = new IdentityPayload('żółw@example.com', [
            'givenName' => [str_repeat('ż', 200)],
        ], 'https://idp.example.com');

        $json = $recorder($sink)->recordFailure(
            'saml2',
            DiagnosticEvent::STAGE_ATTRIBUTES,
            'missing_required_attribute',
            'Missing claim.',
            $payload
        )->toJson();

        Assert::notSame('{"error":"diagnostics_encoding_failed"}', $json);
        Assert::notSame(null, json_decode($json, true));
    },

    'ids are unique per event' => static function () use ($recorder): void {
        $sink = new CollectingSink();
        $writer = $recorder($sink);

        $a = $writer->recordFailure('saml2', DiagnosticEvent::STAGE_PROTOCOL, 'x', 'x');
        $b = $writer->recordFailure('saml2', DiagnosticEvent::STAGE_PROTOCOL, 'x', 'x');

        Assert::notSame($a->id, $b->id);
        Assert::same(16, strlen($a->id));
    },
];
