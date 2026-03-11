<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when an ID token's issued-at timestamp is not credible.
 *
 * This exception represents a temporal trust failure during claim validation.
 * The package raises it when the `iat` claim is missing, malformed, or falls
 * outside the tolerated clock-skew window, which means the token cannot be
 * treated as a plausibly issued authentication artifact.
 *
 * Keeping the issued-at failure separate from expiration and not-before
 * exceptions makes operational diagnosis clearer when provider clocks drift
 * or token minting behavior is inconsistent.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidOidcIssueTimeException extends OidcException
{
    /**
     * Create an exception for an invalid or implausible issued-at claim.
     *
     * Used when the token's `iat` value cannot satisfy the package's
     * time-based trust checks and the token must be rejected before identity
     * resolution completes.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_issue_time'));
    }
}
