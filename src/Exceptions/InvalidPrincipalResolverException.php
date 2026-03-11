<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Exception thrown when the configured principal resolver does not satisfy the
 * package contract.
 *
 * The principal resolver is the central extension point that maps validated
 * external identities onto local authenticatable models. Bootstrapping stops
 * with this exception when the service container returns a class that cannot
 * perform that role, because allowing login flow orchestration to continue
 * would make account linking and sign-in behavior unpredictable.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidPrincipalResolverException extends ConfigurationException
{
    /**
     * Create an exception for an invalid principal resolver binding.
     *
     * This factory is used during service-provider registration after the
     * configured class has been resolved from the container and type-checked.
     * The translated message directs package consumers toward fixing the host
     * application's contract binding rather than debugging later login errors.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.system.errors.invalid_principal_resolver'));
    }
}
