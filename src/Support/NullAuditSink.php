<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Support;

use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Data\SsoProviderRecord;

/**
 * No-op audit sink used when the host application does not provide one.
 *
 * The package can safely emit audit events without guarding every call site.
 * Applications that need persistent audit trails can replace this binding with
 * a real implementation through package configuration.
 *
 * This null object preserves the package's append-only audit API while making
 * the default installation experience non-blocking.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class NullAuditSink implements AuditSinkInterface
{
    /**
     * Intentionally discard audit events when no sink is configured.
     *
     * The method still satisfies the audit contract so callers never need
     * conditional logic around event emission.
     *
     * @param array<string, mixed> $properties
     */
    public function record(string $event, SsoProviderRecord $provider, array $properties = []): void {}
}
