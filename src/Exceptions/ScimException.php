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
 * Base exception for SCIM protocol and pipeline failures.
 *
 * SCIM controllers and middleware use this category for failures that occur
 * after a request has entered the package's provisioning surface but before a
 * valid SCIM response can be completed. Catching this type lets consumers
 * distinguish SCIM-specific failures from interactive SSO login failures or
 * configuration errors elsewhere in the package.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class ScimException extends RuntimeException implements SsoException
{
    use ResolvesExceptionMessage;
}
