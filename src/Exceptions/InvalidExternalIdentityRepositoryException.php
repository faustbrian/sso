<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the configured external-identity repository binding is invalid.
 *
 * The package relies on this repository to find and persist links between
 * remote identities and local principals. This exception is raised during
 * container bootstrap when the configured service resolves successfully but
 * does not honor the package repository contract.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidExternalIdentityRepositoryException extends ConfigurationException
{
    /**
     * Create an exception for an external-identity repository contract mismatch.
     *
     * Centralizing this message keeps repository binding failures aligned with
     * the rest of the package's boot-time configuration exceptions.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.system.errors.invalid_external_identity_repository'));
    }
}
