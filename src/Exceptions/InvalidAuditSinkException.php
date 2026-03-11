<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the configured audit sink binding does not satisfy the package contract.
 *
 * The SSO package records success and failure events during login and SCIM
 * operations. This exception is raised during service provider registration
 * when the configured audit service resolves from the container but does not
 * implement the expected package interface.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidAuditSinkException extends ConfigurationException
{
    /**
     * Create an exception for an invalid audit sink implementation binding.
     *
     * This keeps boot-time contract failures consistent across all configurable
     * package extension points.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.system.errors.invalid_audit_sink'));
    }
}
