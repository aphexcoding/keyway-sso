<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Group;

/**
 * What the Craft layer does with groups the mapping did not produce.
 */
enum GroupSyncMode: string
{
    /** Add mapped groups, leave everything the user already has. Safe default. */
    case Append = 'append';

    /** The IdP is the source of truth: the user ends up in exactly the mapped groups. */
    case Replace = 'replace';
}
