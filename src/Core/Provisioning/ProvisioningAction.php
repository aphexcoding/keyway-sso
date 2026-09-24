<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Provisioning;

enum ProvisioningAction: string
{
    /** Create the account, then sign in. */
    case Create = 'create';

    /** Account exists: apply mapped attributes/groups, then sign in. */
    case Update = 'update';

    /** Account exists: sign in and change nothing. */
    case SignInOnly = 'sign_in_only';

    /** Do not sign in. */
    case Deny = 'deny';
}
