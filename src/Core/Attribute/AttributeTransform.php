<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Attribute;

enum AttributeTransform: string
{
    case None = 'none';
    case Lowercase = 'lowercase';
    case Uppercase = 'uppercase';
}
