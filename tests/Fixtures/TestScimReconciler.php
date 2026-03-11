<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Fixtures;

use Cline\SSO\Contracts\ScimReconcilerInterface;
use Cline\SSO\Data\SsoProviderRecord;

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class TestScimReconciler implements ScimReconcilerInterface
{
    /** @var array<int, string> */
    public static array $providerIds = [];

    public function reconcile(SsoProviderRecord $provider): array
    {
        self::$providerIds[] = $provider->id;

        return [
            'provider_id' => $provider->id,
            'reconciled' => true,
        ];
    }
}
