<?php

declare(strict_types=1);

use Keyway\Sso\Core\Diagnostics\DiagnosticsQuery;
use Keyway\Sso\Plugin;
use Keyway\Sso\Test\Support\Assert;
use Keyway\Sso\controllers\DiagnosticsController;
use craft\web\Controller;

/**
 * The diagnostics panel - the screen and the controller behind it - checked WITHOUT booting
 * Craft.
 *
 * This suite is built on the same admission as sso_controller_test: a controller that renders a
 * template cannot be exercised without a CMS, so what is asserted here are the properties of
 * the FILES, plus the two private helpers that are pure functions. The properties are the ones
 * that would otherwise exist only as prose in a docblock, and all four are security or
 * availability rules rather than style:
 *
 *  1. the admin gate runs BEFORE anything reads the store, so an unauthorised request never
 *     causes a query and never learns whether the table is even there;
 *  2. `requireAdmin(false)` - the argument, which decides whether the screen exists at all on a
 *     production install with `allowAdminChanges` off;
 *  3. a value typed into the URL reaches exactly one place, DiagnosticsQuery::fromInput(), and
 *     travels onward only in its normalised form;
 *  4. the template never disables escaping on a row - every value on a row came from somebody
 *     else's identity provider.
 *
 * Assertions read the source with comments REMOVED. A comment claiming a rule is not the rule;
 * this file is written on the assumption that the next person to edit the controller will edit
 * the comments too, and will not notice a deleted `requireAdmin` line if a paragraph still
 * describes it.
 *
 * WHAT THIS CANNOT VERIFY, stated plainly so a green line is not mistaken for coverage: that
 * the screen renders, that Craft resolves a route to it (there is no route yet - see the class
 * docblock of the controller), that `requireAdmin` actually refuses a non-admin, that the
 * table is readable, that `|datetime` formats in the administrator's timezone, or that the
 * disclosure widgets behave for a screen reader. Those need a running control panel and are
 * the acceptance test.
 */
if (!class_exists(Controller::class)) {
    fwrite(STDOUT, sprintf("%-26s %s\n", 'diagnostics_panel', 'skipped: vendor absent (run composer install)'));

    return [];
}

/** The controller's source, comments stripped. */
$code = static function (): string {
    $source = (string)file_get_contents(
        (string)(new ReflectionClass(DiagnosticsController::class))->getFileName()
    );

    $stripped = '';
    foreach (token_get_all($source) as $token) {
        if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }

        $stripped .= is_array($token) ? $token[1] : $token;
    }

    return $stripped;
};

$templatePath = static function (): string {
    return dirname((string)(new ReflectionClass(Plugin::class))->getFileName())
        . '/templates/_diagnostics.twig';
};

/** The template's source, Twig comments stripped - for the same reason as above. */
$template = static function () use ($templatePath): string {
    return (string)preg_replace(
        '/\{#.*?#\}/s',
        '',
        (string)file_get_contents($templatePath())
    );
};

/**
 * Renders the template with a stand-in layout and stand-in filters.
 *
 * This is the closest thing to seeing the screen that exists without a control panel, and it
 * buys the one assertion no amount of source-reading can make: that a hostile value handed to
 * this template comes out of it as text. `_layouts/cp.twig` is replaced by a bare block holder
 * (the real one needs an application, a queue and a licensed edition), `{% requireAdmin %}` is
 * parsed by a no-op stand-in here because the real node compiles to
 * `Craft::$app->controller->requireAdmin()` and there is no application to call it on, and
 * Craft's filters are replaced by the smallest honest equivalents: `t` substitutes its
 * parameters, `datetime` formats a timestamp.
 *
 * `strict_variables` is on: a variable this template reads and the controller does not pass
 * would be an exception here rather than a silently empty cell in production.
 */
$render = static function (array $variables) use ($templatePath): string {
    $twig = new \Twig\Environment(
        new \Twig\Loader\ArrayLoader([
            'diagnostics' => (string)file_get_contents($templatePath()),
            '_layouts/cp.twig' => '{% block content %}{% endblock %}',
        ]),
        ['strict_variables' => true, 'cache' => false]
    );

    $twig->addFilter(new \Twig\TwigFilter('t', static function (mixed $message, mixed $category = null, mixed $params = null): string {
        $replacements = [];
        foreach (is_array($params) ? $params : [] as $key => $value) {
            $replacements['{' . $key . '}'] = (string)$value;
        }

        return strtr((string)$message, $replacements);
    }));

    $twig->addFilter(new \Twig\TwigFilter('datetime', static fn(mixed $value): string => date('Y-m-d H:i', (int)$value)));

    $twig->registerUndefinedFilterCallback(
        static fn(string $name): \Twig\TwigFilter => new \Twig\TwigFilter($name, static fn(mixed $value = null): string => (string)$value)
    );
    $twig->registerUndefinedFunctionCallback(
        static fn(string $name): \Twig\TwigFunction => new \Twig\TwigFunction($name, static fn(mixed ...$arguments): string => '')
    );

    $twig->addTokenParser(new class extends \Twig\TokenParser\AbstractTokenParser {
        public function parse(\Twig\Token $token): \Twig\Node\Node
        {
            $stream = $this->parser->getStream();

            while (!$stream->test(\Twig\Token::BLOCK_END_TYPE)) {
                $stream->next();
            }

            $stream->expect(\Twig\Token::BLOCK_END_TYPE);

            // A node with no output: Twig refuses anything that renders outside a block in a
            // template that extends another, which is exactly what Craft's own node is - it
            // emits a statement, not content.
            return new \Twig\Node\Nodes([], $token->getLine());
        }

        public function getTag(): string
        {
            return 'requireAdmin';
        }
    });

    // `{% css %}...{% endcss %}`: Craft's node hands the captured body to the view's asset
    // registry, which does not exist here. The stand-in swallows the pair and renders nothing -
    // so the assertion that matters can be made: the stylesheet is NOT in the markup the
    // template itself emits.
    $twig->addTokenParser(new class extends \Twig\TokenParser\AbstractTokenParser {
        public function parse(\Twig\Token $token): \Twig\Node\Node
        {
            $stream = $this->parser->getStream();
            $stream->expect(\Twig\Token::BLOCK_END_TYPE);
            $this->parser->subparse(static fn(\Twig\Token $next): bool => $next->test('endcss'), true);
            $stream->expect(\Twig\Token::BLOCK_END_TYPE);

            return new \Twig\Node\Nodes([], $token->getLine());
        }

        public function getTag(): string
        {
            return 'css';
        }
    });

    return $twig->render('diagnostics', $variables);
};

/**
 * The variables the controller passes, with nothing in them - a screen nobody has used yet.
 *
 * @return array<string, mixed>
 */
$screen = static function (array $overrides = []): array {
    return array_merge([
        'rows' => [],
        'total' => 0,
        'unavailable' => false,
        'outcome' => null,
        'protocol' => null,
        'search' => null,
        'limit' => 50,
        'offset' => 0,
        'filtered' => false,
        'outcomeOptions' => ['success', 'denied', 'error', 'notice'],
        'protocolOptions' => ['saml', 'oidc'],
        'clearUrl' => '/admin/keyway-sso-diagnostics',
        'previousUrl' => null,
        'nextUrl' => null,

        // Null is the clean-URL install. The other case - the path travelling in a query
        // parameter - is exercised by its own case below, because that is the install where
        // a GET form silently loses its way.
        'pathField' => null,
    ], $overrides);
};

/**
 * A row built to the agreed contract rather than to today's DiagnosticRow: the panel is being
 * written against the interface, and a test that instantiates the real class would start
 * failing for reasons that have nothing to do with this screen.
 */
$row = static function (array $overrides = []): object {
    $values = array_merge([
        'id' => 'row-1',
        'timestamp' => 1757800000,
        'protocol' => 'saml',
        'stage' => 'attributes',
        'outcome' => 'denied',
        'reasonCode' => 'attribute_missing',
        'message' => 'The assertion carried no `email` attribute.',
        'issuer' => 'https://idp.example.com/',
        'subject' => 'j****n@example.com',
        'attributes' => [],
        'mapping' => [],
        'decision' => [],
    ], $overrides);

    return new class ($values) {
        public readonly string $id;
        public readonly int $timestamp;
        public readonly string $protocol;
        public readonly string $stage;
        public readonly string $outcome;
        public readonly string $reasonCode;
        public readonly string $message;
        public readonly string $issuer;
        public readonly string $subject;

        /** @var array<string, mixed> */
        private array $values;

        public function __construct(array $values)
        {
            $this->values = $values;
            $this->id = $values['id'];
            $this->timestamp = $values['timestamp'];
            $this->protocol = $values['protocol'];
            $this->stage = $values['stage'];
            $this->outcome = $values['outcome'];
            $this->reasonCode = $values['reasonCode'];
            $this->message = $values['message'];
            $this->issuer = $values['issuer'];
            $this->subject = $values['subject'];
        }

        public function attributes(): array
        {
            return $this->values['attributes'];
        }

        public function mapping(): array
        {
            return $this->values['mapping'];
        }

        public function decision(): array
        {
            return $this->values['decision'];
        }

        public function isSuccess(): bool
        {
            return $this->outcome === 'success';
        }
    };
};

/** Calls one of the controller's private static helpers. */
$call = static function (string $method, array $arguments): mixed {
    return (new ReflectionMethod(DiagnosticsController::class, $method))->invokeArgs(null, $arguments);
};

return [
    'the controller sits where Craft will look for it' => static function (): void {
        $class = new ReflectionClass(DiagnosticsController::class);

        Assert::same('Keyway\Sso\controllers', $class->getNamespaceName());
        Assert::true(is_subclass_of(DiagnosticsController::class, Controller::class));
        Assert::same(
            'controllers',
            basename(dirname((string)$class->getFileName())),
            'PSR-4 maps the lower-cased namespace to a lower-cased directory'
        );

        // Craft's default, restated in the file. A screen showing other people's login
        // metadata is the last place to inherit "who may see this" silently.
        Assert::same(
            false,
            $class->getDefaultProperties()['allowAnonymous'],
            'no action here is anonymous'
        );
    },

    // The order is the rule. A gate placed after the read still returns 403, but the query has
    // already run - and the timing of that query answers "is this plugin installed and has it
    // been migrated" to somebody who is not allowed to ask.
    'the admin gate runs before anything reads the store' => static function () use ($code): void {
        $source = $code();

        $cpRequest = strpos($source, 'requireCpRequest()');
        $admin = strpos($source, 'requireAdmin(false)');
        $reader = strpos($source, 'diagnosticsReader()');

        Assert::true($cpRequest !== false, 'the screen is control-panel only');
        Assert::true($admin !== false, 'the screen is admin only');
        Assert::true($reader !== false, 'the screen reads the store');

        Assert::true((int)$cpRequest < (int)$admin, 'control panel first');
        Assert::true((int)$admin < (int)$reader, 'admin gate before the first read');

        Assert::same(1, substr_count($source, 'requireAdmin('), 'one gate, one place');
        Assert::same(1, substr_count($source, 'diagnosticsReader()'), 'one reader, one place');
    },

    // `requireAdmin()` with no argument defaults to `true`, which also demands
    // `allowAdminChanges` (craft\web\Controller::requireAdmin, vendor .../web/Controller.php
    // lines 496-510). That config is routinely off in production - and a production install
    // with failing logins is exactly who needs this screen. Reading a log is not an
    // administrative change. Craft's own settings/plugins screen takes the same argument.
    'the admin gate does not also demand that admin changes be allowed' =>
        static function () use ($code, $template): void {
            $source = $code();

            Assert::contains('requireAdmin(false)', $source);
            Assert::notContains('requireAdmin()', $source);
            Assert::notContains('requireAdmin(true)', $source);

            // Belt and braces for the day somebody wires the template to a route directly
            // rather than through this controller.
            Assert::contains('{% requireAdmin false %}', $template());
        },

    // An administrator with no permissions screen open is not the audience question here: rows
    // carry a masked account identifier, group names and an e-mail domain belonging to other
    // people. `accessCp` would hand that to every author on the site.
    'access is not delegated to a permission check' => static function () use ($code): void {
        $source = $code();

        Assert::notContains('requirePermission', $source);
        Assert::notContains('accessCp', $source);
        Assert::notContains('checkPermission', $source);
    },

    // The screen has to survive the install it is most needed on: `composer update` without
    // `craft up`, i.e. plugin present, table absent. Anything the reader throws - including
    // the accessor itself being missing - has to become a sentence, not a stack trace.
    'a store that cannot be read becomes a message, not a 500' => static function () use ($code): void {
        $source = $code();

        $try = strpos($source, 'try {');
        $reader = strpos($source, 'diagnosticsReader()');
        $catch = strpos($source, 'catch (Throwable');

        Assert::true($try !== false && $catch !== false, 'the read is guarded');
        Assert::true((int)$try < (int)$reader, 'the guard opens before the read');
        Assert::true((int)$reader < (int)$catch, 'and closes after it');

        // Both calls into the reader are inside the same guard: `total()` throwing after
        // `recent()` succeeded would otherwise be an uncaught exception.
        Assert::true((int)strpos($source, '->total(') < (int)$catch, 'the count is guarded too');

        // The reason goes to the log; a database exception message names tables and sometimes
        // parameters, and this page is read by the customer, not by us.
        $render = substr($source, (int)strpos($source, 'renderTemplate('));
        Assert::notContains('getMessage', $render, 'no exception text reaches the page');
        Assert::contains('getMessage', $source, 'but it is not thrown away either');
    },

    // The one rule that keeps a query-string parameter from becoming a database predicate or a
    // page element: it goes into DiagnosticsQuery::fromInput() and nothing else. The `$raw`
    // prefix marks a value that has not been through it; each one is used exactly twice, and
    // the second use is the call itself.
    'a typed value reaches exactly one place' => static function () use ($code): void {
        $source = $code();

        $call = strrpos($source, 'DiagnosticsQuery::fromInput(');
        Assert::true($call !== false, 'the filters are built from the contract');

        $arguments = substr(
            $source,
            (int)$call,
            (int)strpos($source, ');', (int)$call) - (int)$call
        );

        foreach (['$rawOutcome', '$rawProtocol', '$rawSearch'] as $variable) {
            Assert::same(2, substr_count($source, $variable), $variable . ': assigned once, passed once');
            Assert::contains($variable, $arguments, $variable . ' is passed to fromInput');
        }

        // The page size is asked of the contract rather than assumed, which is the only other
        // call and is filterless by construction.
        Assert::contains('fromInput(null, null, null, $rawLimit, null)', $source);
        Assert::same(2, substr_count($source, 'DiagnosticsQuery::fromInput('));

        // Six parameters read, six reads, and every one of them before the normalising call.
        Assert::same(6, substr_count($source, 'getQueryParam('));
        Assert::true(
            (int)strrpos($source, 'getQueryParam(') < (int)strpos($source, 'DiagnosticsQuery::fromInput('),
            'nothing is read from the request after the query is built'
        );

        Assert::notContains('$_GET', $source);
        Assert::notContains('getQueryParams()', $source);
        Assert::notContains('->getBodyParam', $source);
        Assert::notContains('->getParam(', $source);
    },

    'nothing unnormalised is handed to the template' => static function () use ($code): void {
        $source = $code();
        $render = substr($source, (int)strpos($source, 'renderTemplate('));

        Assert::notContains('$raw', $render, 'the view sees the query object\'s answers only');
        Assert::notContains('getQueryParam', $render);

        // Control panel mode, like every other template this plugin renders: a site-mode lookup
        // would resolve `keyway-sso/...` against the customer's own templates directory.
        Assert::contains('View::TEMPLATE_MODE_CP', $source);
    },

    // Pure function, so it can be measured rather than described. `page` exists because pagers
    // and people count in pages; the contract counts in offsets.
    'the page number is translated into an offset, and overflow collapses' =>
        static function () use ($call): void {
            Assert::same(120, $call('offsetFrom', [120, 3, 50]), 'an explicit offset wins');
            Assert::same(100, $call('offsetFrom', [null, 3, 50]), 'page 3 of 50');
            Assert::same(0, $call('offsetFrom', [null, 1, 50]), 'page 1 starts at nothing');
            Assert::same(null, $call('offsetFrom', [null, null, 50]), 'no paging asked for');

            // Below the first page stays negative here and is clamped by the contract, which is
            // the single place clamping happens.
            Assert::same(-50, $call('offsetFrom', [null, 0, 50]));

            // `?page=<twenty digits>` turns an int multiplication into a float, and a float
            // where fromInput() declares `?int` is a TypeError under strict_types - a 500 on
            // the one screen whose job is to work when everything else is broken.
            Assert::same(null, $call('offsetFrom', [null, PHP_INT_MAX, 50]), 'overflow is not a crash');
            Assert::same(null, $call('offsetFrom', [null, PHP_INT_MIN, 50]));
        },

    'a number that is not a number is absent, not zero' => static function () use ($call): void {
        Assert::same(50, $call('intOrNull', ['50']));
        Assert::same(-5, $call('intOrNull', ['-5']));
        Assert::same(7, $call('intOrNull', [7]));

        // The difference that matters: null means "parameter absent", which the contract turns
        // into its default. A cast would turn `?limit=abc` into `?limit=0` and then into a
        // clamped 1, i.e. a one-row page nobody asked for.
        Assert::same(null, $call('intOrNull', ['12abc']));
        Assert::same(null, $call('intOrNull', ['1e3']));
        Assert::same(null, $call('intOrNull', ['']));
        Assert::same(null, $call('intOrNull', ['99999999999999999999999']));
        Assert::same(null, $call('intOrNull', [['array', 'from', 'the', 'url']]));
        Assert::same(null, $call('intOrNull', [null]));
    },

    // Self-links are built from what the query object gives back, never from what arrived, so a
    // rejected `?outcome=<script>` is simply not in the next page's URL.
    'pager links carry normalised filters only' => static function () use ($call): void {
        if (!class_exists(DiagnosticsQuery::class)) {
            fwrite(STDOUT, sprintf(
                "\n%-26s %s\n",
                'diagnostics_panel',
                'DiagnosticsQuery absent: the pager parameters were not verified'
            ));

            return;
        }

        $query = DiagnosticsQuery::fromInput('"><script>', 'ftp', "  looking for this  ", 5, 10);
        $params = $call('pageParams', [$query, 15]);

        Assert::same(15, $params['offset']);
        Assert::same(5, $params['limit']);
        Assert::false(isset($params['outcome']), 'an unusable outcome is not echoed back');
        Assert::false(isset($params['protocol']), 'an unusable protocol is not echoed back');
        Assert::same('looking for this', $params['search'] ?? null, 'a usable search survives, trimmed');

        Assert::notContains('script', json_encode($params, JSON_THROW_ON_ERROR));
    },

    'the template is where the controller says it is' => static function () use ($code, $templatePath): void {
        Assert::same('keyway-sso/_diagnostics.twig', DiagnosticsController::TEMPLATE);
        Assert::true(is_file($templatePath()), 'the diagnostics template exists');
        Assert::contains('self::TEMPLATE', $code());
    },

    // The strongest statement available without a control panel: the file is valid Twig and
    // compiles to PHP. Unknown filters and functions are stubbed (they are Craft's, and Craft
    // is not booted); `{% requireAdmin %}` is parsed with Craft's OWN token parser rather than
    // a stand-in, so the tag is checked the way Craft will read it.
    'the template parses and compiles' => static function () use ($templatePath): void {
        if (!class_exists(\Twig\Environment::class)) {
            fwrite(STDOUT, sprintf(
                "\n%-26s %s\n",
                'diagnostics_panel',
                'Twig absent: the template was not compiled'
            ));

            return;
        }

        $source = (string)file_get_contents($templatePath());

        $twig = new \Twig\Environment(new \Twig\Loader\ArrayLoader(['diagnostics' => $source]));
        $twig->registerUndefinedFilterCallback(
            static fn(string $name): \Twig\TwigFilter => new \Twig\TwigFilter($name, static fn(...$arguments): string => '')
        );
        $twig->registerUndefinedFunctionCallback(
            static fn(string $name): \Twig\TwigFunction => new \Twig\TwigFunction($name, static fn(...$arguments): string => '')
        );
        $twig->addTokenParser(new \craft\web\twig\tokenparsers\RequireAdminTokenParser());
        // Craft's own parser for `{% css %}`, configured the way craft\web\twig\Extension
        // registers it - so a tag pair Craft would refuse is refused here too.
        $cssParser = new \craft\web\twig\tokenparsers\RegisterResourceTokenParser(
            'css',
            \craft\helpers\Template::class . '::css'
        );
        $cssParser->allowTagPair = true;
        $cssParser->allowOptions = true;
        $twig->addTokenParser($cssParser);

        $twigSource = new \Twig\Source($source, 'diagnostics', $templatePath());

        Assert::doesNotThrow(
            static fn() => $twig->parse($twig->tokenize($twigSource)),
            'the template is valid Twig'
        );

        $compiled = '';
        Assert::doesNotThrow(
            static function () use ($twig, $twigSource, &$compiled): void {
                $compiled = $twig->compileSource($twigSource);
            },
            'the template compiles to PHP'
        );

        Assert::true(strlen($compiled) > 1000, 'something was actually compiled');
    },

    // A successful row at the provisioning stage is a login that was ACCEPTED: the account write
    // and the session start are still ahead of it, and both can fail. Before 1.0.2 that row was
    // labelled "Signed in", so `no_cp_access` left a green "Signed in" beside the red row that
    // said the person never got in.
    '"Signed in" is said by the session row only; an accepted decision says "Accepted"' =>
        static function () use ($render, $screen, $row): void {
            $html = $render($screen([
                'rows' => [
                    $row(['outcome' => 'error', 'stage' => 'session', 'reasonCode' => 'no_cp_access']),
                    $row(['outcome' => 'success', 'stage' => 'provisioning', 'reasonCode' => 'user_created']),
                ],
                'total' => 2,
            ]));

            Assert::contains('Accepted', $html);
            Assert::contains('<code>no_cp_access</code>', $html);
            Assert::notContains('Signed in', $html, 'nobody was signed in, and the screen does not say so');

            $both = $render($screen([
                'rows' => [
                    $row(['outcome' => 'success', 'stage' => 'session', 'reasonCode' => 'signed_in']),
                    $row(['outcome' => 'success', 'stage' => 'provisioning', 'reasonCode' => 'user_updated']),
                ],
                'total' => 2,
            ]));

            Assert::same(1, substr_count($both, 'Signed in'));
            Assert::same(2, substr_count($both, 'status green'), 'both rows are good news');
        },

    // The filter selects by stored outcome, and `success` now covers two labels.
    'the outcome filter names both kinds of successful row' =>
        static function () use ($render, $screen): void {
            $html = $render($screen(['outcome' => 'success', 'filtered' => true]));

            Assert::contains('Accepted or signed in', $html);
        },

    // The stylesheet goes through Craft's view ({% css %}), not into the body as a bare
    // <style>: that is what lets a site with a Content-Security-Policy nonce keep its policy.
    'the screen registers its stylesheet instead of inlining it' =>
        static function () use ($template, $render, $screen): void {
            $source = $template();

            Assert::notContains('<style', $source);
            Assert::contains('{% css %}', $source);
            Assert::contains('{% endcss %}', $source);
            Assert::notContains('<style', $render($screen([])));
            Assert::notContains('keyway-diagnostics-pairs {', $render($screen([])), 'the rules are not in the markup');
        },

    // Every value on a row arrived from somebody else's identity provider. Masked is not the
    // same as harmless: an issuer of `<img src=x onerror=...>` would be script running in an
    // administrator's session, delivered by anyone who can reach the login endpoint. Twig's
    // autoescaping is the entire defence.
    'the template never turns escaping off' => static function () use ($template): void {
        $source = $template();

        Assert::notContains('|raw', $source);
        Assert::notContains('autoescape', $source);
        Assert::notContains('|json_encode', $source);

        // The row fields, each rendered as text.
        foreach (['row.subject', 'row.issuer', 'row.reasonCode', 'row.message', 'row.id'] as $field) {
            Assert::contains('{{ ' . $field . ' }}', $source, $field . ' is printed as text');
        }
    },

    'every sentence on the screen is translatable' => static function () use ($template): void {
        $source = $template();

        // No sentence may go through `t` without this plugin's category: `|t` alone means
        // Craft's `site` category, which is the customer's translations, not ours.
        Assert::same(
            substr_count($source, '|t('),
            substr_count($source, "|t('keyway-sso'"),
            'every translated string names this plugin\'s category'
        );
        Assert::true(substr_count($source, "|t('keyway-sso'") > 30, 'the screen is translated, not partly');
        Assert::notContains("|t('app')", $source);

        // Times are formatted by Craft, in the administrator's locale and timezone - not by a
        // hand-rolled format string that would be wrong on half the installs in the world.
        Assert::contains('|datetime(', $source);
        Assert::notContains('|date(', $source);
    },

    // The three states this screen has to survive, each with its own wording. "No rows" is not
    // an error, "no rows matching a filter" is not the same as "no rows", and "the table is not
    // there" is neither - and an empty table with no explanation reads as a broken product.
    'the empty states are designed rather than left blank' => static function () use ($template): void {
        $source = $template();

        Assert::contains('{% if unavailable %}', $source);
        Assert::contains('php craft up', $source, 'the missing-table state says what to do');

        Assert::contains('No sign-in attempts have been recorded yet', $source);
        Assert::contains('No entries match the current filters', $source);

        // The way out of a filter typo, without editing the URL.
        Assert::same(3, substr_count($source, '{{ clearUrl }}'), 'form action, clear button, escape hatch');
    },

    'the columns support asks about are all there' => static function () use ($template): void {
        $source = $template();

        foreach ([
            'row.timestamp',
            'row.outcome',
            'row.protocol',
            'row.stage',
            'row.reasonCode',
            'row.subject',
            'row.issuer',
            'row.attributes()',
            'row.mapping()',
            'row.decision()',
        ] as $field) {
            Assert::contains($field, $source, $field . ' is on the screen');
        }

        // Colour is never the only signal: each outcome cell carries the word as well.
        Assert::contains('outcomeLabels[row.outcome] ?? row.outcome', $source);
        Assert::contains('aria-hidden="true"', $source, 'the status dot is decoration');

        // Details expand in place. A second page would mean a second route, a second
        // controller action and a second gate to get wrong.
        Assert::contains('<details', $source);
        Assert::contains('<summary>', $source);
    },

    // The measurement, rather than the argument. A hostile issuer is handed to the real
    // template and the output is inspected: this is what `|raw` would break, and asserting on
    // rendered bytes says so in a way that grepping for a filter name cannot.
    'a hostile value comes out of the screen as text' => static function () use ($render, $screen, $row): void {
        $html = $render($screen([
            'rows' => [
                $row([
                    'issuer' => '<script>alert(1)</script>',
                    'subject' => '"><img src=x onerror=alert(1)>',
                    'reasonCode' => 'group_no_match<svg onload=alert(1)>',
                    'message' => 'Nothing matched <b>anything</b>.',
                    'attributes' => ['<b>groups</b>' => ['</td><script>alert(1)</script>']],
                    'mapping' => ['email' => '<i>nobody@example.com</i>'],
                    'decision' => ['allowed' => false, 'reason' => '<hr>'],
                ]),
            ],
            'total' => 1,
        ]));

        Assert::notContains('<script>', $html, 'no element from a row survives as markup');
        Assert::notContains('<img src=x', $html);
        Assert::notContains('<svg onload', $html);
        Assert::notContains('</td><script', $html);

        // `onerror=` DOES appear in the output, as five escaped characters inside a table cell,
        // and that is the point: the attack survives as prose. Asserting its absence would be
        // asserting that the panel hides evidence from the person debugging.
        Assert::contains('&lt;img src=x onerror=alert(1)&gt;', $html);

        // And it is still READABLE, which is the other half of the job: escaped, not dropped.
        Assert::contains('&lt;script&gt;alert(1)&lt;/script&gt;', $html);
        Assert::contains('group_no_match&lt;svg', $html);
        Assert::contains('&lt;b&gt;groups&lt;/b&gt;', $html, 'claim names are shown in full');
        Assert::contains('&lt;i&gt;nobody@example.com&lt;/i&gt;', $html, 'the mapping is shown');
    },

    'the three empty states each render their own sentence' => static function () use ($render, $screen): void {
        $nothingYet = $render($screen());
        Assert::contains('No sign-in attempts have been recorded yet', $nothingYet);
        Assert::notContains('No entries match', $nothingYet);
        Assert::notContains('<table', $nothingYet, 'an empty table is not an empty state');

        $filtered = $render($screen([
            'filtered' => true,
            'outcome' => 'error',
            'total' => 0,
        ]));
        Assert::contains('No entries match the current filters', $filtered);
        Assert::notContains('No sign-in attempts have been recorded yet', $filtered);
        // The way back, without editing the URL.
        Assert::contains('href="/admin/keyway-sso-diagnostics"', $filtered);

        $broken = $render($screen(['unavailable' => true]));
        Assert::contains('php craft up', $broken, 'it says what to do');
        Assert::notContains('No sign-in attempts have been recorded yet', $broken);
        Assert::notContains('<table', $broken);
    },

    'a row renders with its outcome, its raw reason code and its details' =>
        static function () use ($render, $screen, $row): void {
            $html = $render($screen([
                'rows' => [
                    $row([
                        'outcome' => 'success',
                        'stage' => 'session',
                        'protocol' => 'oidc',
                        'reasonCode' => 'signed_in',
                        'attributes' => ['groups' => ['craft-admins', 'craft-editors']],
                        'mapping' => ['groups' => ['Administrators'], 'email' => 'j****n@example.com'],
                        'decision' => ['allowed' => true, 'created' => false, 'note' => null],
                    ]),
                ],
                'total' => 1,
            ]));

            Assert::contains('<code>signed_in</code>', $html, 'the code support asks for, verbatim');
            Assert::contains('status green', $html, 'signed in reads as signed in');
            Assert::contains('Signed in', $html, 'and says so in words, not only in colour');
            Assert::same(1, substr_count($html, 'Signed in'), 'once: on the row, not in the filter');
            Assert::contains('OpenID Connect', $html, 'a label, not the stored identifier');
            Assert::contains('2025-09', $html, 'the timestamp went through a date formatter');

            // The nested structures, rendered rather than dumped.
            Assert::contains('craft-editors', $html);
            Assert::contains('Administrators', $html);
            Assert::contains('yes', $html, 'a boolean decision reads as a word');
            Assert::contains('(none)', $html, 'and a null one is not an empty cell');

            Assert::contains('<details', $html);
            Assert::contains('j****n@example.com', $html, 'the subject stays masked, as stored');
        },

    'the pager only points where there is somewhere to go' => static function () use ($render, $screen, $row): void {
        $firstPage = $render($screen([
            'rows' => [$row(), $row(['id' => 'row-2'])],
            'total' => 5,
            'limit' => 2,
            'nextUrl' => '/admin/keyway-sso-diagnostics?offset=2',
        ]));

        Assert::contains('Showing 1-2 of 5', $firstPage, 'the count is a sentence, not three numbers');
        Assert::contains('rel="next"', $firstPage);
        Assert::notContains('rel="prev"', $firstPage);

        $secondPage = $render($screen([
            'rows' => [$row()],
            'total' => 5,
            'limit' => 2,
            'offset' => 4,
            'previousUrl' => '/admin/keyway-sso-diagnostics?offset=2',
        ]));

        Assert::contains('Showing 5-5 of 5', $secondPage);
        Assert::contains('rel="prev"', $secondPage);
        Assert::notContains('rel="next"', $secondPage);
    },

    // The filter form is the screen's state. It has to come back showing what actually ran -
    // including the part that was thrown away, which is why the controller passes the query
    // object's answers and not the request's.
    'the filter form redisplays the filters that were applied' =>
        static function () use ($render, $screen): void {
            $html = $render($screen([
                'filtered' => true,
                'outcome' => 'denied',
                'protocol' => 'saml',
                'search' => 'acme',
                'limit' => 25,
            ]));

            Assert::contains('<option value="denied" selected>', $html);
            Assert::contains('<option value="saml" selected>', $html);
            Assert::notContains('<option value="oidc" selected>', $html);
            Assert::contains('value="acme"', $html, 'the search box still holds the search');
            Assert::contains('name="limit" value="25"', $html, 'the page size survives filtering');

            // Every control is labelled - the panel is opened under pressure, by people using
            // screen readers among others.
            foreach (['keyway-filter-outcome', 'keyway-filter-protocol', 'keyway-filter-search'] as $id) {
                Assert::contains('for="' . $id . '"', $html, $id . ' has a label');
                Assert::contains('id="' . $id . '"', $html, $id . ' is the control it labels');
            }
        },

    // Regression test. The reader is contractually forbidden to throw, so an
    // install whose migration never ran answers `[]` and `0` - identical to an install where
    // nobody has signed in. Deciding "unavailable" from the catch block therefore showed the
    // customer "no sign-in attempts have been recorded yet" and left them waiting for rows that
    // could never arrive. The distinction has to be ASKED for; measured: replacing the call with
    // `$unavailable = false` left the whole suite green before this case existed.
    'the missing-table state is asked for, not inferred from an exception' =>
        static function () use ($code): void {
            $source = $code();

            Assert::contains('$reader->isReady()', $source, 'the store is asked whether it exists');

            $ready = strpos($source, 'isReady()');
            $recent = strpos($source, '$reader->recent(');

            Assert::true($ready !== false && $recent !== false, 'both calls are present');
            Assert::true($ready < $recent, 'the question comes before the reads it guards');
        },

    // Regression test for the rule the last case in this file asserts on the rendered screen. That
    // template half was covered; the CONTROLLER half - the decision that moved out of the
    // template - was not, and a `return null;` at the
    // top of pathField() left the suite fully green. Worse, the value it produced was wrong:
    // UrlHelper::cpUrl() prepends the control-panel trigger BEFORE the path goes into the query
    // parameter (UrlHelper.php:701-704, :811), while Request::getPathInfo() hands it back with
    // the trigger stripped. Submitting `?p=sso/diagnostics` makes Craft score the request as a
    // SITE request - the plugin registers control-panel rules only - so the administrator got a
    // 404 on the front end. Asserted on the VALUE, across the three install shapes.
    'the hidden path field carries the value Craft itself would have put in the query' =>
        static function (): void {
            Assert::same(
                ['name' => 'p', 'value' => 'admin/sso/diagnostics'],
                DiagnosticsController::pathFieldFor('p', false, false, 'sso/diagnostics', 'admin'),
                'the default install gets the trigger back'
            );

            Assert::same(
                ['name' => 'p', 'value' => 'sso/diagnostics'],
                DiagnosticsController::pathFieldFor('p', false, false, 'sso/diagnostics', ''),
                'an empty trigger adds no empty segment'
            );

            // Both of these are installs where Craft puts the path in the URL path, so a hidden
            // field would be noise - and `?p=` duplicating the address is how a bookmarked URL
            // starts disagreeing with itself.
            Assert::null(
                DiagnosticsController::pathFieldFor('p', true, false, 'sso/diagnostics', 'admin'),
                'clean URLs need no field'
            );
            Assert::null(
                DiagnosticsController::pathFieldFor('p', false, true, 'sso/diagnostics', 'admin'),
                'usePathInfo keeps the path in the path'
            );
            Assert::null(
                DiagnosticsController::pathFieldFor(null, false, false, 'sso/diagnostics', 'admin'),
                'no path param, no field'
            );
        },

    // ...and the wiring between the pure decision and the screen, because the pure case above
    // cannot see it: `return null;` at the top of pathField() reverted the production half of
    // this rule with the whole suite still green (measured). Source assertions,
    // like every other rule in this file that needs a booted Craft to exercise.
    'the screen actually asks for the path field' => static function () use ($code): void {
        $source = $code();

        Assert::contains("'pathField' => self::pathField()", $source, 'the template is given it');
        Assert::contains('return self::pathFieldFor(', $source, 'and pathField() defers to the rule');
        Assert::notContains('return null;' . "\n" . '        $general', $source, 'with nothing short-circuiting it');
    },

    // Regression test. With Craft's default `omitScriptNameInUrls = false` this
    // screen lives at `/index.php?p=admin/sso/diagnostics` - the path is a QUERY PARAMETER - and
    // a GET form replaces the query string with its own fields. Without the hidden field the
    // administrator pressing "Apply" leaves the control panel entirely and lands on the site's
    // home page with `?outcome=denied` attached, while the "Clear" anchor keeps working: a
    // screen that looks half broken, on the install configuration Craft ships by default.
    'the filter form keeps the path on an install that carries it in the query string' =>
        static function () use ($render, $screen): void {
            $withParam = $render($screen([
                'pathField' => ['name' => 'p', 'value' => 'admin/sso/diagnostics'],
            ]));

            Assert::contains(
                '<input type="hidden" name="p" value="admin/sso/diagnostics">',
                $withParam,
                'the path travels with the submitted filters'
            );

            // And is absent where Craft would not have used it: no redundant `?p=` on an
            // install with clean URLs.
            Assert::notContains('name="p"', $render($screen()), 'clean URLs get a clean form');
        },

    // The screen shows raw reason codes and, until this link existed, nothing in the product said
    // where they are explained. It has to be there in EVERY state - the administrator who most
    // needs the troubleshooting page is the one looking at "could not be read" or at a refusal.
    'every state of the screen links to the troubleshooting guide, in a new tab' =>
        static function () use ($render, $screen, $row): void {
            $link = '<a href="https://keyway.aphexcoding.tech/craft-cms-sso-not-working"'
                . ' target="_blank" rel="noopener">';

            $states = [
                'empty' => $screen(),
                'unavailable' => $screen(['unavailable' => true]),
                'filtered, no match' => $screen(['filtered' => true, 'outcome' => 'denied']),
                'with rows' => $screen(['rows' => [$row()], 'total' => 1]),
            ];

            foreach ($states as $name => $variables) {
                Assert::same(1, substr_count($render($variables), $link), $name . ': one link, no more');
            }
        },
];
