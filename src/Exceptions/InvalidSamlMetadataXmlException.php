<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Exception thrown when remote SAML metadata cannot be parsed into a usable
 * descriptor document.
 *
 * Metadata import and validation rely on this exception to differentiate
 * descriptor-document failures from assertion-response failures. It marks the
 * administrative path where provider bootstrap data such as certificates,
 * entity IDs, and SSO URLs cannot be extracted safely, preventing stale or
 * malformed metadata from being cached as trusted configuration.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidSamlMetadataXmlException extends SamlException
{
    /**
     * Create an exception for invalid or unreadable SAML metadata XML.
     *
     * The factory is used during metadata refresh and configuration import
     * flows, where package operators need a clear signal that the descriptor
     * document itself is invalid rather than merely incomplete.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.saml.errors.invalid_metadata_xml'));
    }
}
