<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when imported SAML metadata does not expose a usable SSO endpoint.
 *
 * The package raises this while normalizing provider metadata for persistence
 * or validation. Without a SingleSignOnService URL the provider record cannot
 * initiate browser redirects, so the metadata is considered structurally
 * incomplete even if other descriptor fields are present.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingSingleSignOnUrlException extends SamlException
{
    /**
     * Create an exception for metadata missing the SAML SSO destination URL.
     *
     * This factory is used once metadata parsing has succeeded but endpoint
     * extraction cannot locate any supported SingleSignOnService location.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.missing_single_sign_on_url'));
    }
}
