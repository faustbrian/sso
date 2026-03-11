<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

use RuntimeException;

/**
 * Base exception for failures in the package's interactive login lifecycle.
 *
 * This abstraction groups browser-oriented SSO login errors that occur after
 * package boot but before a principal is successfully authenticated into the
 * host application. It gives callers a broad catch target for login flow
 * invariants while still allowing concrete exceptions to describe individual
 * failure conditions precisely.
 *
 * The base exists to separate user-facing login orchestration failures from
 * lower-level protocol exceptions and boot-time configuration exceptions.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class LoginException extends RuntimeException implements SsoException
{
    use ResolvesExceptionMessage;
}
