<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the ID token cannot be parsed as the expected JWT structure.
 *
 * This exception captures failures in the compact-token parsing phase, after
 * the package has obtained a candidate ID token but before claim validation
 * can proceed. It signals that the token does not contain the structural
 * segments or parser output required for signed JWT validation.
 *
 * Keeping token-structure failures distinct from token-header and claim-level
 * exceptions makes it clearer whether the package rejected the token because
 * it was malformed or because a specific trust check later in the pipeline
 * failed.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidOidcTokenStructureException extends OidcException
{
    /**
     * Create an exception for an ID token with an invalid JWT structure.
     *
     * Returned when the package cannot parse the compact token string into the
     * encrypted-free JWT form required for signature and claim validation.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.oidc.errors.invalid_token_structure'));
    }
}
