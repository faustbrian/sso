<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Fixtures;

use Cline\SSO\Contracts\SsoStrategy;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\ValueObjects\ResolvedIdentity;
use Illuminate\Http\Request;

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class TestStrategy implements SsoStrategy
{
    public function buildAuthorizationUrl(SsoProviderRecord $provider, Request $request, string $state, string $nonce): string
    {
        return 'https://example.test/authorize';
    }

    public function resolveIdentity(SsoProviderRecord $provider, Request $request, string $nonce): ResolvedIdentity
    {
        return new ResolvedIdentity(
            attributes: [],
            email: null,
            issuer: 'https://example.test',
            subject: 'subject',
        );
    }

    public function validateConfiguration(SsoProviderRecord $provider): array
    {
        return [];
    }

    public function importConfiguration(SsoProviderRecord $provider): array
    {
        return [];
    }

    public function refreshMetadata(SsoProviderRecord $provider): array
    {
        return [];
    }
}
