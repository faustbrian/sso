<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Facades;

use Cline\SSO\SsoManager;
use Illuminate\Support\Facades\Facade;

/**
 * Facade entry point for the package's orchestration manager.
 *
 * This exposes provider lookup, validation, metadata refresh, and external
 * identity persistence through Laravel's facade API for application code and
 * internal package consumers that prefer static-style access. The facade does
 * not introduce new behavior; it keeps every call routed through the same
 * singleton manager that coordinates repository access and driver resolution.
 *
 * Using a facade here is intentionally an ergonomic layer, not a second API.
 * Consumers who use the facade and consumers who inject the manager both talk
 * to the same orchestration boundary.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class Sso extends Facade
{
    /**
     * Resolve the container binding that backs facade dispatch.
     *
     * Returning the manager class keeps facade calls aligned with the package's
     * orchestrator instead of bypassing its provider lookup and strategy
     * resolution rules or accidentally resolving a secondary service.
     */
    protected static function getFacadeAccessor(): string
    {
        return SsoManager::class;
    }
}
