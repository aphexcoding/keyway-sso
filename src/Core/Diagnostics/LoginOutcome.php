<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Diagnostics;

enum LoginOutcome: string
{
    /** The user was signed in. */
    case Success = 'success';

    /** Everything verified, but policy said no (domain, groups, JIT off, suspended). */
    case Denied = 'denied';

    /** Something was wrong with the request itself (signature, state, missing claims). */
    case Error = 'error';

    /**
     * The login worked, and something about HOW it worked is worth an administrator's attention.
     *
     * Added for the one degradation this plugin accepts on purpose: a cross-site POST callback
     * on a site without HTTPS cannot carry a browser-binding cookie (Core\Login\BrowserBinding),
     * so the login runs unbound. That must not read as Success - nothing is wrong with the
     * response - and must not read as Error either, because the person was signed in. A silent
     * degradation is the only outcome that would be wrong.
     */
    case Notice = 'notice';
}
