<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Fixtures;

use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Data\SsoProviderRecord;

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class TestAuditSink implements AuditSinkInterface
{
    /** @var array<int, array{event: string, provider: string, properties: array<string, mixed>}> */
    public static array $events = [];

    public function record(string $event, SsoProviderRecord $provider, array $properties = []): void
    {
        self::$events[] = [
            'event' => $event,
            'provider' => $provider->id,
            'properties' => $properties,
        ];
    }
}
