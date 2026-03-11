<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Data;

/**
 * Immutable projection of a stored external-identity link.
 *
 * The package persists these records after a successful link or provisioning
 * flow so future logins can skip heuristic matching and resolve the same local
 * principal directly from issuer and subject claims. Repository implementations
 * return this value object instead of active models so higher layers can reason
 * about identity linkage without persistence concerns leaking upward.
 *
 * The combination of provider, issuer, and subject is the stable remote
 * identity key. The linked principal points back into the application domain,
 * and the email snapshot is a denormalized convenience field for support,
 * reporting, and audit use cases. Because this is a projection rather than an
 * active record, callers can safely pass it across login, audit, and
 * provisioning boundaries without accidentally coupling those flows to a
 * concrete storage implementation.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class ExternalIdentityRecord
{
    /**
     * @param null|string $id            Persisted record identifier, if one has been assigned
     * @param null|string $emailSnapshot Last known email associated with the link for support, audit,
     *                                   and operator-facing troubleshooting flows
     */
    public function __construct(
        public ?string $id,
        public ?string $emailSnapshot,
        public string $issuer,
        public PrincipalReference $linkedPrincipal,
        public string $providerId,
        public string $subject,
    ) {}

    /**
     * Return a copy of the record with an updated email snapshot.
     *
     * Email snapshots are denormalized for audit and support flows and may be
     * refreshed independently from the stable issuer and subject linkage. The
     * method leaves every identity key untouched so callers can update display
     * context without mutating the actual link semantics. This is used during
     * callback resolution when a previously linked identity signs in with a
     * newer email claim but still represents the same upstream subject.
     */
    public function withEmailSnapshot(?string $emailSnapshot): self
    {
        return new self(
            id: $this->id,
            emailSnapshot: $emailSnapshot,
            issuer: $this->issuer,
            linkedPrincipal: $this->linkedPrincipal,
            providerId: $this->providerId,
            subject: $this->subject,
        );
    }
}
