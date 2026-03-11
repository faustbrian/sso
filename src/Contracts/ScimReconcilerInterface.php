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
 * Applies SCIM membership reconciliation side effects for a provider.
 *
 * Reconciliation jobs call into this contract after choosing the provider to
 * process. Implementations own the details of fetching remote memberships,
 * mapping them to local records, applying any writes or removals, and
 * reporting a structured summary for operator visibility.
 *
 * This contract exists because membership semantics differ substantially
 * between applications. The package orchestrates when reconciliation happens,
 * but the host application decides what a membership means and how drift should
 * be corrected.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface ScimReconcilerInterface
{
    /**
     * Reconcile the provider's SCIM memberships and return an execution
     * summary.
     *
     * The returned summary is intended for job logging and operational tooling,
     * so implementations should include enough structured detail to explain what
     * changed, skipped, or failed during reconciliation.
     *
     * @return array<string, mixed>
     */
    public function reconcile(SsoProviderRecord $provider): array;
}
