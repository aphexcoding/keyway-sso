<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Group;

/**
 * Supported match kinds.
 *
 * Deliberately no regular expressions. An administrator-supplied regex is an attack surface
 * (catastrophic backtracking, and a pattern like `.*` silently matching every directory group
 * straight into an admin rule) and the three modes below cover the real directory layouts:
 * flat group names, `craft-*` prefixes, and `*-admins` suffixes.
 */
enum GroupMatchType: string
{
    case Exact = 'exact';
    case Prefix = 'prefix';
    case Suffix = 'suffix';
}
