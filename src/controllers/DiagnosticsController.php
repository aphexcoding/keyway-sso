<?php

declare(strict_types=1);

namespace Keyway\Sso\controllers;

use Craft;
use craft\helpers\UrlHelper;
use craft\web\Controller;
use craft\web\View;
use Keyway\Sso\Config\AuthProtocol;
use Keyway\Sso\Core\Diagnostics\DiagnosticsQuery;
use Keyway\Sso\Core\Diagnostics\LoginOutcome;
use Keyway\Sso\Plugin;
use Throwable;
use yii\web\Response;

/**
 * The diagnostics screen: why THAT person did not get in at THAT hour.
 *
 * ------------------------------------------------------------------------------------------
 * WHY THIS SCREEN IS A FEATURE AND NOT A NICETY
 * ------------------------------------------------------------------------------------------
 *
 * A refused visitor is shown one sentence, always the same one, and never a reason
 * (Core\Login\LoginRefusal::PUBLIC_MESSAGE - the wording must not vary with the cause, or the
 * wording becomes an oracle). That is right for the visitor and useless for the administrator,
 * who is the person who has to fix the identity provider. Without a screen that tells the
 * administrator what the visitor may not be told, every failed login at a customer's site is a
 * support ticket addressed to us - which is the opposite of the hands-off operation this
 * product is sold on. The panel is the support channel.
 *
 * ------------------------------------------------------------------------------------------
 * ADMIN ONLY, AND WHY `accessCp` WOULD BE THE WRONG GATE
 * ------------------------------------------------------------------------------------------
 *
 * Rows carry a masked account identifier, group names and an e-mail domain belonging to other
 * people. Masked is not anonymous: `j****n@acme-legal.example` plus a group name plus a
 * timestamp is personal data about somebody who never chose to be in this table. Every user
 * with control panel access is not the right audience for that; an administrator is.
 *
 * `requireAdmin(false)` - the argument matters. craft\web\Controller::requireAdmin() (lines
 * 496-510 of vendor/craftcms/cms/src/web/Controller.php) runs three checks in order: a login is
 * required, `getUser()->getIsAdmin()` must be true, and THEN, only when the argument is true,
 * `allowAdminChanges` must be on. On a production install that flag is routinely off - it is
 * how Craft stops schema-affecting edits outside of development - and that is precisely the
 * install where a failing login has to be diagnosable. Reading a log is not an administrative
 * change. Craft draws the same line on its own read-mostly screens: `settings/plugins/index`
 * opens with `{% requireAdmin false %}` and then renders itself read-only.
 *
 * ------------------------------------------------------------------------------------------
 * THE ROUTE THIS ACTION IS REACHABLE ON
 * ------------------------------------------------------------------------------------------
 *
 * `Plugin::CP_ROUTES` maps `sso/diagnostics` here, and the settings screen links to it through
 * `Plugin::diagnosticsUrl()` - the plugin registers no navigation item, so that link is the way
 * in. The path deliberately does NOT begin with the plugin handle: see the case
 * `no control panel route starts with the plugin handle` in test/sso_controller_test.php, which
 * is a guest-interception rule in Craft rather than a style preference. The action URL
 * (`<cp-trigger>/actions/keyway-sso/diagnostics/index`) still works and still produces the
 * uglier self-links described on `currentUrl()` below.
 */
class DiagnosticsController extends Controller
{
    /** Query-string parameters. Read once each, in actionIndex, and passed straight on. */
    public const PARAM_OUTCOME = 'outcome';
    public const PARAM_PROTOCOL = 'protocol';
    public const PARAM_SEARCH = 'search';
    public const PARAM_LIMIT = 'limit';
    public const PARAM_OFFSET = 'offset';
    public const PARAM_PAGE = 'page';

    public const TEMPLATE = 'keyway-sso/_diagnostics.twig';

    /**
     * @inheritdoc
     *
     * Craft's default, restated because "who may open this" is the whole point of the file.
     */
    protected array|bool|int $allowAnonymous = false;

    /**
     * The panel. Reads filters from the query string, shows the newest attempts first.
     */
    public function actionIndex(): Response
    {
        // Order matters and is asserted by diagnostics_panel_test: the gates run before
        // anything touches the reader, so an unauthorised request never causes a query at all.
        $this->requireCpRequest();
        $this->requireAdmin(false);

        // `$raw*` means: typed by whoever opened the URL, not yet anything. Each of these is
        // used EXACTLY TWICE - assigned here, handed to DiagnosticsQuery::fromInput() below -
        // and the test counts those two uses. There is deliberately no third path: no local
        // trimming, no `in_array` of our own, nothing reaching the template or a URL except
        // through the normalised query object.
        $rawOutcome = self::stringOrNull($this->request->getQueryParam(self::PARAM_OUTCOME));
        $rawProtocol = self::stringOrNull($this->request->getQueryParam(self::PARAM_PROTOCOL));
        $rawSearch = self::stringOrNull($this->request->getQueryParam(self::PARAM_SEARCH));
        $rawLimit = self::intOrNull($this->request->getQueryParam(self::PARAM_LIMIT));
        $rawOffset = self::intOrNull($this->request->getQueryParam(self::PARAM_OFFSET));
        $rawPage = self::intOrNull($this->request->getQueryParam(self::PARAM_PAGE));

        // The contract speaks in offsets; people and pagers speak in pages. Translating one
        // into the other needs the page size, and the page size is DiagnosticsQuery's answer
        // (it clamps `limit` to MIN/MAX), never a number invented here - a locally assumed 50
        // against a clamped 200 is how a pager starts skipping rows.
        $pageSize = DiagnosticsQuery::fromInput(null, null, null, $rawLimit, null)->limit();

        $query = DiagnosticsQuery::fromInput(
            $rawOutcome,
            $rawProtocol,
            $rawSearch,
            $rawLimit,
            self::offsetFrom($rawOffset, $rawPage, $pageSize)
        );

        $rows = [];
        $total = 0;
        $unavailable = false;

        try {
            $reader = Plugin::getInstance()->diagnosticsReader();

            // ASKED, NOT INFERRED FROM AN EXCEPTION. The reader is contractually forbidden to
            // throw, so an install whose migration never ran answers `[]` and `0` exactly like
            // an install where nobody has signed in yet. Those two states need opposite
            // sentences on screen - "run the pending database updates" versus "nothing has
            // happened yet" - and only the store knows which one is true.
            $unavailable = !$reader->isReady();

            if (!$unavailable) {
                $rows = $reader->recent($query);
                $total = $reader->total($query);
            }
        } catch (Throwable $error) {
            // THE ONE PLACE THIS SCREEN IS ALLOWED TO FAIL SOFTLY, and it has to. The table is
            // created by a migration; a customer who ran `composer update` and not `craft up`
            // has the plugin without the table, and the panel they open to find out why logins
            // fail must not itself be the thing that breaks. It also covers the reader being
            // absent altogether (Plugin::diagnosticsReader() missing or returning null).
            // A reader that honours its contract reports a missing table through isReady()
            // above; this block is what is left for the kinds of failure nobody declared.
            //
            // The reason goes to the log, never to the page: the message of a database
            // exception carries table names, DSN fragments and sometimes parameters.
            $unavailable = true;
            Craft::warning(
                'The diagnostics panel could not read its store: ' . $error->getMessage(),
                __METHOD__
            );
        }

        $path = $this->currentUrl();

        return $this->renderTemplate(self::TEMPLATE, [
            'rows' => $rows,
            'total' => $total,
            'unavailable' => $unavailable,
            'pathField' => self::pathField(),

            // Normalised, never raw: what the template redisplays in the filter form is what
            // the query actually ran with. A mistyped `?outcome=succes` shows as "all
            // outcomes", because that is what happened.
            'outcome' => $query->outcome(),
            'protocol' => $query->protocol(),
            'search' => $query->search(),
            'limit' => $query->limit(),
            'offset' => $query->offset(),

            // Computed here rather than in Twig so the template never has to ask what an empty
            // filter looks like. `hasFilters()` on the query would say the same thing, but it
            // is outside the agreed contract, and this screen is being built against the
            // contract rather than against today's implementation.
            'filtered' => $query->outcome() !== null
                || $query->protocol() !== null
                || $query->search() !== null,

            'outcomeOptions' => array_map(
                static fn(LoginOutcome $case): string => $case->value,
                LoginOutcome::cases()
            ),
            // Only the protocols a login can actually arrive over: `disabled` is a settings
            // state, and no stored row can carry it.
            'protocolOptions' => array_values(array_map(
                static fn(AuthProtocol $case): string => $case->value,
                array_filter(AuthProtocol::cases(), static fn(AuthProtocol $case): bool => $case->isEnabled())
            )),

            'clearUrl' => UrlHelper::cpUrl($path),
            'previousUrl' => $query->offset() > 0
                ? UrlHelper::cpUrl($path, self::pageParams($query, max(0, $query->offset() - $query->limit())))
                : null,
            'nextUrl' => ($query->offset() + $query->limit()) < $total
                ? UrlHelper::cpUrl($path, self::pageParams($query, $query->offset() + $query->limit()))
                : null,
        ], View::TEMPLATE_MODE_CP);
    }

    /**
     * The control panel path of the request being answered, for self-links.
     *
     * `getPathInfo()` on craft\web\Request returns the requested path with the control panel
     * trigger already stripped (Request.php:387-394), which is exactly what cpUrl() wants back.
     *
     * WHAT IT RETURNS WHEN THERE IS NO ROUTE YET: on an action request the path still contains
     * the action trigger, so the self-links come back as
     * `<cp>/actions/keyway-sso/diagnostics/index?...`. Those links work - they re-run this
     * action - they are merely ugly, and they tidy themselves up the moment a control panel
     * route points here.
     */
    /**
     * The hidden field a GET form needs on an install whose URLs carry the path in a query
     * parameter - or null where it would be noise.
     *
     * WHY A FORM ON THIS SCREEN NEEDS ONE AT ALL. With Craft's default
     * `omitScriptNameInUrls = false`, this screen's own address is
     * `https://host/index.php?p=admin/sso/diagnostics`: the path lives in the query string.
     * Submitting a GET form REPLACES the query string with the form's fields, so `p` would
     * disappear and "Apply" would land the administrator on the site's home page carrying
     * `?outcome=denied`. The "Clear" link, an ordinary anchor, would keep working - a screen
     * that is half broken in a way that reads as our bug.
     *
     * The three-part test is not invented here. It is the branch `UrlHelper::_createUrl()`
     * takes (vendor/craftcms/cms/src/helpers/UrlHelper.php:804) when it decides to put the path
     * into `pathParam` rather than into the URL path, with `showScriptName` resolved the way
     * `cpUrl()` resolves it - `!omitScriptNameInUrls` (line 773). When Craft would not have used
     * the query parameter, this returns null and the form stays clean.
     *
     * @return array{name: string, value: string}|null
     */
    private static function pathField(): ?array
    {
        $general = Craft::$app->getConfig()->getGeneral();

        return self::pathFieldFor(
            $general->pathParam,
            (bool)$general->omitScriptNameInUrls,
            (bool)$general->usePathInfo,
            Craft::$app->getRequest()->getPathInfo(),
            (string)$general->cpTrigger
        );
    }

    /**
     * The decision behind pathField(), with Craft taken out of it so it can be checked.
     *
     * THE CONTROL PANEL TRIGGER IS THE WHOLE POINT OF THIS METHOD EXISTING SEPARATELY, and the
     * first version of the fix got it wrong in a way no test could see. `UrlHelper::cpUrl()`
     * runs `prependCpTrigger()` BEFORE handing the path to `_createUrl()`, so the value Craft
     * puts into the query parameter is `admin/sso/diagnostics` - trigger included
     * (UrlHelper.php:701-704 and :811). `craft\web\Request::getPathInfo()` returns the path with
     * the trigger already STRIPPED (`Request.php:301-302`): `sso/diagnostics`.
     *
     * Submitting the form with the stripped value therefore produced
     * `?p=sso/diagnostics&outcome=denied`, which Craft scores as a SITE request (the path does
     * not start with the trigger) - and the plugin registers control-panel rules only, so the
     * administrator got a 404 on the front end instead of their filtered list. A different error
     * page than before the fix, the same person thrown out of the control panel.
     *
     * An install whose `cpTrigger` is empty (the control panel served from its own base URL)
     * passes through unchanged: `prependCpTrigger()` filters empties out.
     *
     * @return array{name: string, value: string}|null
     */
    public static function pathFieldFor(
        ?string $pathParam,
        bool $omitScriptNameInUrls,
        bool $usePathInfo,
        string $pathInfo,
        string $cpTrigger
    ): ?array {
        if ($pathParam === null || $pathParam === '' || $omitScriptNameInUrls || $usePathInfo) {
            return null;
        }

        return [
            'name' => $pathParam,
            'value' => implode('/', array_filter([$cpTrigger, $pathInfo])),
        ];
    }

    private function currentUrl(): string
    {
        return $this->request->getPathInfo();
    }

    /**
     * The current filters plus an offset, for a pager link.
     *
     * Every value comes back out of the query object, so nothing a visitor typed is echoed into
     * a URL: a rejected `?outcome=<script>` is simply absent from the links.
     *
     * @return array<string, int|string>
     */
    private static function pageParams(DiagnosticsQuery $query, int $offset): array
    {
        $params = [
            'limit' => $query->limit(),
            'offset' => $offset,
        ];

        foreach ([
            self::PARAM_OUTCOME => $query->outcome(),
            self::PARAM_PROTOCOL => $query->protocol(),
            self::PARAM_SEARCH => $query->search(),
        ] as $name => $value) {
            if ($value !== null) {
                $params[$name] = $value;
            }
        }

        return $params;
    }

    /**
     * `offset` wins; `page` is translated; anything unusable collapses to "the first page".
     *
     * The result is still handed to DiagnosticsQuery::fromInput(), which clamps it - this is a
     * translation, not a second validator. The overflow branch is not theoretical: `?page=` with
     * twenty digits turns an int multiplication into a float, and a float where fromInput()
     * declares `?int` is a TypeError under strict_types, i.e. a 500 on a screen whose entire
     * job is to still work when everything else is broken.
     */
    private static function offsetFrom(?int $offset, ?int $page, int $pageSize): ?int
    {
        if ($offset !== null) {
            return $offset;
        }

        if ($page === null) {
            return null;
        }

        $product = ($page - 1) * $pageSize;

        return is_int($product) ? $product : null;
    }

    private static function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Strict: `FILTER_VALIDATE_INT` rejects `12abc`, `1e3` and anything past PHP_INT_MAX rather
     * than casting it to something that looks deliberate.
     */
    private static function intOrNull(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        if (!is_string($value)) {
            return null;
        }

        $parsed = filter_var($value, FILTER_VALIDATE_INT);

        return $parsed === false ? null : $parsed;
    }
}
