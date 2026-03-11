<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Exception thrown when the configured provider repository cannot fulfill the
 * package persistence contract.
 *
 * Provider repositories back the package's lookup and mutation logic for SSO
 * provider records. This exception surfaces during boot when an application
 * swaps that repository seam with an incompatible implementation, stopping the
 * package before protocol resolution, metadata refresh, or login orchestration
 * can depend on undefined persistence behavior.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidProviderRepositoryException extends ConfigurationException
{
    /**
     * Create an exception for an invalid provider repository binding.
     *
     * The factory is called after the service container resolves the configured
     * repository class and the package confirms it does not implement the
     * expected interface. The message therefore describes a package setup
     * problem, not a runtime data-access failure.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.system.errors.invalid_provider_repository'));
    }
}
