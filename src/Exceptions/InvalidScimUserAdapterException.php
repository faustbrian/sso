<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the configured SCIM user adapter does not satisfy the package
 * contract.
 *
 * The user adapter is the package boundary for SCIM user lookup and mutation.
 * This boot-time exception protects the SCIM user endpoints from resolving a
 * container binding that cannot provide the expected protocol-to-domain bridge.
 *
 * It exists as a dedicated configuration failure so application maintainers can
 * distinguish adapter wiring problems from runtime SCIM request errors.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidScimUserAdapterException extends ConfigurationException
{
    /**
     * Create an exception for an invalid SCIM user adapter binding.
     *
     * Used when the resolved service does not implement the user adapter
     * interface consumed by the package's SCIM user controllers.
     *
     * @return self Exception describing the invalid user adapter
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.system.errors.invalid_scim_user_adapter'));
    }
}
