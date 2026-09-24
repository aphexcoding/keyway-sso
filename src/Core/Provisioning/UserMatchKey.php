<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Provisioning;

/**
 * Which field links an IdP identity to an existing Craft account.
 */
enum UserMatchKey: string
{
    case Email = 'email';
    case Username = 'username';
}
