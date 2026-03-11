<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\ValueObjects;

/**
 * Normalized identity payload returned by a protocol strategy callback.
 *
 * Strategies can receive wildly different provider-specific claim sets, but
 * the rest of the package only needs a stable issuer/subject pair, an optional
 * email address, and the raw attribute map for application-specific linking
 * decisions. This immutable value object is that normalization boundary.
 *
 * It deliberately stops short of resolving a local principal. The value object
 * represents a trusted external identity after protocol validation but before
 * application policy decides how that identity maps into the local account
 * model. That separation is important: protocol strategies establish trust in
 * the upstream identity, while principal resolvers apply local linking and
 * provisioning policy afterward.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class ResolvedIdentity
{
    /**
     * @param array<string, mixed> $attributes Raw provider claims preserved for
     *                                         downstream provisioning and audit
     *                                         decisions beyond the core fields
     * @param null|string          $email      Optional email claim extracted from
     *                                         the provider when one is available;
     *                                         this may be absent or unsuitable
     *                                         for linking even when protocol
     *                                         validation succeeds
     * @param string               $issuer     Trusted issuer identifier after
     *                                         protocol validation
     * @param string               $subject    Trusted provider subject used as
     *                                         the durable external identity key
     *                                         within the issuer namespace
     */
    public function __construct(
        public array $attributes,
        public ?string $email,
        public string $issuer,
        public string $subject,
    ) {}
}
