<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Support;

use Cline\SSO\Contracts\ScimReconcilerInterface;
use Cline\SSO\Data\SsoProviderRecord;

/**
 * No-op SCIM reconciler for applications that have not implemented mapping.
 *
 * Jobs and commands can still execute against the contract, but they will not
 * alter local memberships until the binding is replaced with a real adapter.
 * This keeps scheduled reconciliation safe in partially integrated
 * installations.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class NullScimReconciler implements ScimReconcilerInterface
{
    /**
     * Return an empty reconciliation result to signal no applied changes.
     *
     * Callers can still audit or log the result without special-casing the null
     * implementation.
     *
     * @return array<string, mixed>
     */
    public function reconcile(SsoProviderRecord $provider): array
    {
        return [];
    }
}
