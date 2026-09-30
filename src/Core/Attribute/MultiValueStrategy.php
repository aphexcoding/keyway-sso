<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Attribute;

/**
 * How to collapse a multi-valued IdP attribute into one user field.
 */
enum MultiValueStrategy: string
{
    case First = 'first';
    case Last = 'last';
    case Join = 'join';
}
