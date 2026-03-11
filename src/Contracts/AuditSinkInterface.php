<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Contracts;

use Cline\SSO\Data\SsoProviderRecord;

/**
 * Records security-significant SSO events outside the package core.
 *
 * The package emits audit events for administrative changes, emergency
 * recovery actions, and other security-relevant transitions, but it does not
 * assume where those events should be stored or forwarded. This contract lets
 * the host application bridge package events into its own compliance,
 * observability, or incident-response tooling.
 *
 * Implementations should treat audit emission as a side-effect boundary rather
 * than a place to change package state. Callers expect recording to be
 * append-only from the perspective of domain behavior.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface AuditSinkInterface
{
    /**
     * Persist or emit a package-defined audit event.
     *
     * Implementations should treat the event name as a stable identifier and
     * the provider record as the primary subject the event pertains to. The
     * optional properties payload is reserved for structured context that helps
     * operators reconstruct why the event occurred.
     *
     * @param array<string, mixed> $properties
     */
    public function record(string $event, SsoProviderRecord $provider, array $properties = []): void;
}
