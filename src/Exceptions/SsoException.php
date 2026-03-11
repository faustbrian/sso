<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

use Throwable;

/**
 * Marker interface for every exception owned by the SSO package.
 *
 * Consumers can catch this interface to handle package-originated failures
 * without also swallowing unrelated application exceptions. Abstract protocol
 * base exceptions and standalone framework-facing exceptions both implement
 * this contract so the package exposes one top-level catch boundary.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface SsoException extends Throwable {}
