<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Cline\Morphism\MorphismServiceProvider;
use Cline\SSO\SsoServiceProvider;
use Cline\VariableKeys\Enums\PrimaryKeyType;
use Cline\VariableKeys\VariableKeysServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use Tests\Fixtures\TestAuditSink;
use Tests\Fixtures\TestPrincipalResolver;
use Tests\Fixtures\TestScimGroupAdapter;
use Tests\Fixtures\TestScimReconciler;
use Tests\Fixtures\TestScimUserAdapter;
use Tests\Fixtures\TestUser;

use function base64_encode;
use function str_repeat;

/**
 * @author Brian Faust <brian@cline.sh>
 * @internal
 */
abstract class TestCase extends Orchestra
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        TestAuditSink::$events = [];
        TestScimUserAdapter::$users = [];
        TestScimGroupAdapter::$groups = [];
        TestScimReconciler::$providerIds = [];
        TestPrincipalResolver::$allowLink = true;
        TestPrincipalResolver::$allowSignIn = true;
        TestPrincipalResolver::$allowProvision = true;
    }

    protected function getPackageProviders($app): array
    {
        return [
            MorphismServiceProvider::class,
            SsoServiceProvider::class,
            VariableKeysServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app->make(Repository::class)->set('app.key', 'base64:'.base64_encode(str_repeat('a', 32)));
        $app->make(Repository::class)->set('database.default', 'testing');
        $app->make(Repository::class)->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app->make(Repository::class)->set('sso.primary_key_type', 'ulid');
        $app->make(Repository::class)->set('sso.foreign_keys.owner.type', 'id');
        $app->make(Repository::class)->set('sso.foreign_keys.owner.owner_key', 'id');
        $app->make(Repository::class)->set('sso.foreign_keys.principal.type', 'id');
        $app->make(Repository::class)->set('sso.foreign_keys.principal.owner_key', 'id');
        $app->make(Repository::class)->set('sso.models.owner', TestUser::class);
        $app->make(Repository::class)->set('sso.models.principal', TestUser::class);
        $app->make(Repository::class)->set('sso.contracts.principal_resolver', TestPrincipalResolver::class);
        $app->make(Repository::class)->set('sso.contracts.audit_sink', TestAuditSink::class);
        $app->make(Repository::class)->set('sso.contracts.scim_user_adapter', TestScimUserAdapter::class);
        $app->make(Repository::class)->set('sso.contracts.scim_group_adapter', TestScimGroupAdapter::class);
        $app->make(Repository::class)->set('sso.contracts.scim_reconciler', TestScimReconciler::class);
    }

    protected function defineDatabaseMigrations(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->increments('id');
            $table->string('email')->unique();
            $table->string('name')->nullable();
            $table->string('password')->nullable();
            $table->timestamps();
        });

        Schema::create('sso_providers', function (Blueprint $table): void {
            $table->variablePrimaryKey(PrimaryKeyType::ULID);
            $table->variableForeignKey('tenant_id', PrimaryKeyType::ID);
            $table->string('driver');
            $table->string('scheme')->unique();
            $table->string('display_name');
            $table->string('authority');
            $table->string('client_id');
            $table->text('client_secret');
            $table->string('valid_issuer')->nullable();
            $table->boolean('validate_issuer')->default(true);
            $table->boolean('enabled')->default(false);
            $table->boolean('is_default')->default(false);
            $table->boolean('enforce_sso')->default(false);
            $table->boolean('scim_enabled')->default(false);
            $table->string('scim_token_hash')->nullable()->index();
            $table->timestamp('scim_last_used_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('last_login_succeeded_at')->nullable();
            $table->timestamp('last_login_failed_at')->nullable();
            $table->text('last_failure_reason')->nullable();
            $table->timestamp('last_metadata_refreshed_at')->nullable();
            $table->timestamp('last_metadata_refresh_failed_at')->nullable();
            $table->text('last_metadata_refresh_error')->nullable();
            $table->timestamp('last_validated_at')->nullable();
            $table->timestamp('last_validation_succeeded_at')->nullable();
            $table->timestamp('last_validation_failed_at')->nullable();
            $table->text('last_validation_error')->nullable();
            $table->timestamp('secret_rotated_at')->nullable();
            $table->json('settings')->nullable();
            $table->timestamps();
            $table->softDeletes();
        });

        Schema::create('external_identities', function (Blueprint $table): void {
            $table->variablePrimaryKey(PrimaryKeyType::ULID);
            $table->variableForeignKey('user_id', PrimaryKeyType::ID);
            $table->variableForeignKey('sso_provider_id', PrimaryKeyType::ULID);
            $table->string('issuer');
            $table->string('subject');
            $table->string('email_snapshot')->nullable();
            $table->timestamps();
            $table->unique(['sso_provider_id', 'issuer', 'subject']);
        });
    }

    protected function defineRoutes($router): void
    {
        if (!$router instanceof Router) {
            return;
        }

        $router->get('/dashboard/{locale}', static fn (string $locale): string => 'dashboard-'.$locale)
            ->name('dashboard');
    }
}
