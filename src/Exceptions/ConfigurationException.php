<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

use InvalidArgumentException;

/**
 * Base exception for package bootstrap and configuration contract failures.
 *
 * These exceptions are raised while the package is reading application config,
 * validating extension-point bindings, or normalizing package-owned runtime
 * settings. They represent setup-time failures that should stop the package
 * from continuing with partially valid container bindings or route metadata.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class ConfigurationException extends InvalidArgumentException implements SsoException
{
    use ResolvesExceptionMessage;
}
