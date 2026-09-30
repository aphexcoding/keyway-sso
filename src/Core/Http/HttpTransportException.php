<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Http;

use RuntimeException;

/**
 * The request could not be completed: DNS, TLS, timeout, size cap.
 *
 * This is NOT a protocol rejection. The protocol layer catches it and turns it into an
 * IdentityReaderException with a reason code, so that the login screen never shows a curl
 * message and the diagnostics record still gets the detail.
 */
final class HttpTransportException extends RuntimeException
{
}
