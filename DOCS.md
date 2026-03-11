# SSO Package Guide

## Overview

`cline/sso` is an opinionated Laravel package for:

- browser-based SSO login flows
- OpenID Connect (`oidc`) providers
- SAML 2.0 (`saml2`) providers
- SCIM 2.0 provisioning endpoints
- provider metadata import and refresh
- external identity linking
- operational recovery and reconciliation tooling

The package owns its SSO persistence layer and exposes the subsystem
through package services and contracts. Consumer applications are
expected to provide only application-specific behavior, such as how a
resolved external identity maps to a local account, how provisioning is
performed, and where audit events should be written.

The main package-facing runtime entry point is
`Cline\SSO\SsoManager`.

For terminology and real-world mappings, read
[`TERMINOLOGY.md`](TERMINOLOGY.md) first.

## Mental Model

The package uses four core terms:

- `owner`: the local boundary that owns one or more SSO provider
  configurations
- `provider`: the upstream identity provider configuration
- `subject`: the external identity asserted by that provider
- `principal`: the local identity the package links the external subject
  to

In a typical B2B Laravel app this often maps to:

- `owner` -> `Organization`, `Workspace`, `MerchantAccount`
- `principal` -> `User`, `Member`, `Admin`

The package persists provider state and external identity links, but it
does not define your application's principal, membership, or audit
model.

## What The Package Owns

The package owns:

- SSO provider persistence
- external identity persistence
- package migrations
- package routes for browser login and SCIM
- default Eloquent repositories
- OIDC and SAML protocol handling
- metadata import, validation, and refresh orchestration
- SCIM HTTP protocol behavior
- maintenance commands

The consumer application owns:

- principal lookup and provisioning policy
- authorization for whether a principal may link or sign in
- SCIM user and group mutation behavior
- audit-event persistence or forwarding
- application-specific UI around provider management

## Installation

Install the package:

```bash
composer require cline/sso
```

Publish the configuration if you want to customize it:

```bash
php artisan vendor:publish --tag=sso-config
```

Publish the migrations if you want them in your application instead of
loading from the package:

```bash
php artisan vendor:publish --tag=sso-migrations
```

Run your migrations:

```bash
php artisan migrate
```

## Quick Start

The fastest useful integration consists of four steps:

1. Install the package and run the SSO migrations.
2. Configure your `owner` and `principal` model classes in
   `config/sso.php`.
3. Bind the required contracts.
4. Create at least one provider record and send users to the package's
   SSO entry route.

### Minimal Configuration

The important defaults live in `config/sso.php`:

```php
return [
    'guard' => 'web',
    'primary_key_type' => env('SSO_PRIMARY_KEY_TYPE', 'id'),

    'login' => [
        'redirect_to' => '/',
        'redirect_route_name' => null,
    ],

    'routes' => [
        'enabled' => true,
        'prefix' => 'sso',
        'name_prefix' => 'sso.',
        'scim_enabled' => true,
        'scim_prefix' => 'scim/v2',
        'scim_name_prefix' => 'sso.scim.',
    ],

    'models' => [
        'owner' => App\Models\Organization::class,
        'principal' => App\Models\User::class,
    ],
];
```

### Required Consumer Bindings

These contracts must be provided by the host application:

- `Cline\SSO\Contracts\PrincipalResolverInterface`
- `Cline\SSO\Contracts\AuditSinkInterface`
- `Cline\SSO\Contracts\ScimUserAdapterInterface`
- `Cline\SSO\Contracts\ScimGroupAdapterInterface`
- `Cline\SSO\Contracts\ScimReconcilerInterface`

Bind them in your application service provider:

```php
use App\Support\Sso\AppAuditSink;
use App\Support\Sso\AppPrincipalResolver;
use App\Support\Sso\AppScimGroupAdapter;
use App\Support\Sso\AppScimReconciler;
use App\Support\Sso\AppScimUserAdapter;
use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Contracts\PrincipalResolverInterface;
use Cline\SSO\Contracts\ScimGroupAdapterInterface;
use Cline\SSO\Contracts\ScimReconcilerInterface;
use Cline\SSO\Contracts\ScimUserAdapterInterface;

$this->app->singleton(
    PrincipalResolverInterface::class,
    AppPrincipalResolver::class,
);

$this->app->singleton(
    AuditSinkInterface::class,
    AppAuditSink::class,
);

$this->app->singleton(
    ScimUserAdapterInterface::class,
    AppScimUserAdapter::class,
);

$this->app->singleton(
    ScimGroupAdapterInterface::class,
    AppScimGroupAdapter::class,
);

$this->app->singleton(
    ScimReconcilerInterface::class,
    AppScimReconciler::class,
);
```

Once these bindings exist, the package can run the browser login flow,
SCIM endpoints, metadata refresh commands, and external identity
linking.

## Public Integration Surface

### `SsoManager`

`Cline\SSO\SsoManager` is the normal package façade.

Use it for:

- listing enabled login providers
- searching providers administratively
- loading a provider by ID, scheme, or SCIM token hash
- creating, updating, and deleting providers
- finding, saving, and deleting external identity links
- validating provider configuration
- importing provider metadata
- refreshing provider metadata

Typical usage:

```php
use Cline\SSO\Data\ProviderSearchCriteria;
use Cline\SSO\Enums\BooleanFilter;
use Cline\SSO\SsoManager;

public function __invoke(SsoManager $sso): array
{
    return $sso->searchProviders(
        new ProviderSearchCriteria(
            enabled: BooleanFilter::True,
        ),
    );
}
```

### Repository Contracts

The repository contracts remain public:

- `ProviderRepositoryInterface`
- `ExternalIdentityRepositoryInterface`

They are advanced seams for replacing persistence behavior. Most
applications should keep the package defaults and work through
`SsoManager`.

## Required Consumer Contracts

### `PrincipalResolverInterface`

This contract is the most important consumer-owned policy boundary.

It answers:

- how the package finds a local principal by email
- how the package resolves a principal from a linked external identity
- whether a principal may be linked
- whether a principal may be auto-provisioned
- how to build a stable principal reference
- whether the principal may sign in
- which side effects should happen after login

If you are integrating the package into an existing application, this
contract is where your account-linking and access policy belongs.

### `AuditSinkInterface`

This receives structured package audit events. The package does not
assume a storage backend or audit product.

Typical uses:

- write to an activity-log table
- forward to a SIEM or webhook
- emit security analytics events

### `ScimUserAdapterInterface`

This maps your local principal/user model to SCIM `User` resources.

It must provide:

- list
- create
- find
- replace
- patch

All returned data should already be SCIM-shaped arrays.

### `ScimGroupAdapterInterface`

This maps your local group or role model to SCIM `Group` resources.

It must provide:

- list
- create
- find
- patch
- delete

### `ScimReconcilerInterface`

This is the background reconciliation boundary. The package decides when
reconciliation runs; your application decides what reconciliation means.

Typical uses:

- sync group membership from remote identity data
- remove stale mappings
- emit operational summaries

## Configuration Reference

The package configuration is grouped by concern.

### `guard`

The Laravel auth guard used for SSO sign-in.

Use the same guard that manages session behavior for the principal type
signing in through SSO.

### `primary_key_type`

Defines the package primary key strategy for package-owned models.

Typical values:

- `id`
- `uuid`
- `ulid`

The package integrates this with `cline/variable-keys`.

### `login`

Controls post-login redirects.

- `redirect_to`: direct path fallback
- `redirect_route_name`: named route override

If both are set, the route name wins.

### `cache`

Controls protocol metadata caching.

- `discovery_ttl`: OIDC discovery document cache
- `jwks_ttl`: OIDC signing key cache
- `metadata_ttl`: generic provider metadata cache

### `drivers`

Maps configured provider driver names to strategy classes.

Defaults:

- `oidc` -> `Cline\SSO\Drivers\Oidc\OidcStrategy`
- `saml2` -> `Cline\SSO\Drivers\Saml\SamlStrategy`

You can replace or extend these if you need custom protocol behavior.

### `routes`

Controls route registration and naming.

Browser login routes:

- `enabled`
- `middleware`
- `prefix`
- `name_prefix`
- `index_name`
- `callback_name`

SCIM routes:

- `scim_enabled`
- `scim_prefix`
- `scim_name_prefix`
- `scim_middleware`

### `models`

Defines application model classes for:

- `owner`
- `principal`

These are consumer model classes, not package persistence models.

### `table_names`

Controls the package table names for:

- providers
- external identities

Use this only if you need non-default table names.

### `foreign_keys`

Controls how the package stores references to the consumer's owner and
principal models.

Each section contains package-facing persistence settings such as:

- foreign key column
- referenced key name
- key type

### `repositories`

Advanced override point for replacing the default Eloquent repositories.

Most consumers should keep the defaults.

### `contracts`

Defines the concrete classes the package resolves for:

- principal resolver
- audit sink
- SCIM user adapter
- SCIM group adapter
- SCIM reconciler

## Browser Routes

When route registration is enabled, the package registers:

- `GET /{prefix}` -> provider chooser page
- `GET /{prefix}/{scheme}/redirect` -> begin external login
- `GET|POST /{prefix}/{scheme}/callback` -> process provider callback

By default with `prefix = sso`, that becomes:

- `GET /sso`
- `GET /sso/{scheme}/redirect`
- `GET|POST /sso/{scheme}/callback`

### Route Names

By default:

- chooser: `sso.index`
- redirect: `sso.redirect`
- callback: `sso.callback`

These can be renamed through `routes.name_prefix`,
`routes.index_name`, and `routes.callback_name`.

## SCIM Routes

When SCIM is enabled, the package registers:

- `GET ServiceProviderConfig`
- `GET Schemas`
- `GET ResourceTypes`
- `GET Users`
- `POST Users`
- `GET Users/{user}`
- `PUT Users/{user}`
- `PATCH Users/{user}`
- `GET Groups`
- `POST Groups`
- `GET Groups/{group}`
- `PATCH Groups/{group}`
- `DELETE Groups/{group}`

By default these are mounted under `/scim/v2`.

The package applies the configured SCIM middleware stack and then its
own SCIM authentication middleware alias internally.

## Provider Records

The package persists provider records for:

- driver
- scheme
- display name
- authority
- client credentials
- issuer validation settings
- enablement and default-provider flags
- SCIM enablement and token hash
- metadata health and refresh timestamps
- validation timestamps and failures
- login health information
- driver-specific settings

This record is exposed to package consumers as
`Cline\SSO\Data\SsoProviderRecord`.

Most application code should consume that immutable record rather than
package Eloquent models.

## External Identities

The package persists external identity links between:

- provider
- issuer
- subject
- local principal reference

This is what makes later logins durable and deterministic.

The public immutable representation is
`Cline\SSO\Data\ExternalIdentityRecord`.

## Driver Behavior

### OIDC

The built-in OIDC strategy supports:

- discovery document lookup
- JWKS retrieval and caching
- ID token validation
- issuer and audience checks
- metadata import
- metadata refresh

Use `oidc` for providers such as:

- Microsoft Entra ID / Azure AD
- Okta OIDC
- Auth0 OIDC

### SAML 2

The built-in SAML strategy supports:

- redirect initiation
- callback/assertion parsing
- metadata import
- metadata refresh
- certificate handling
- signed response validation
- optional signed AuthnRequests

Use `saml2` for providers exposing SAML-based identity federation.

## Commands

The package provides three operational commands.

### `sso:refresh-metadata`

Refreshes metadata for matching providers.

Options:

- `--scheme=*`
- `--dispatch-sync`

Use this after upstream issuer, endpoint, or certificate changes.

### `sso:reconcile-scim-identities`

Reconciles SCIM-backed memberships for matching providers.

Options:

- `--scheme=*`
- `--dispatch-sync`

Use this when:

- reconciliation jobs were missed
- adapter behavior changed
- you need to repair provisioning drift

### `sso:recover-access`

Emergency recovery command that disables SSO enforcement for matching
providers.

Arguments and options:

- `ownerType?`
- `ownerId?`
- `--scheme=*`
- `--disable-provider`

Use this only for break-glass recovery scenarios.

## Typical Login Flow

The high-level browser flow is:

1. User loads the chooser page.
2. User selects an enabled provider.
3. Package redirects to the external provider.
4. Provider calls back to the package callback route.
5. Strategy validates the callback and resolves a trusted identity.
6. Package tries to find a stored external identity link.
7. If none exists, the package asks the principal resolver to:
   - find by email
   - decide whether linking is allowed
   - optionally auto-provision
8. Package persists the external identity link.
9. Package asks whether the principal may sign in.
10. Package signs in through the configured guard.
11. Package runs post-login side effects through the resolver.

## Typical SCIM Flow

The high-level SCIM flow is:

1. Remote SCIM client sends a bearer token.
2. Package hashes the token and resolves the owning provider.
3. Package verifies that SCIM is enabled for that provider.
4. Package forwards the request to the configured SCIM adapter.
5. Adapter returns SCIM-shaped arrays.
6. Package serializes those arrays into SCIM responses.

## Example Integration Shape

A common application setup looks like this:

- package owns `sso_providers`
- package owns `external_identities`
- app binds `PrincipalResolverInterface`
- app binds audit sink and SCIM adapters
- app uses `SsoManager` for provider-management UI and runtime reads
- app keeps its own `Organization` and `User` models without renaming
  them to match package vocabulary

That means your application can stay domain-specific while the package
owns protocol, persistence, and orchestration behavior.

## Testing Your Integration

Test your package integration at three levels:

### 1. Login Flow

Write targeted tests for:

- chooser rendering
- successful callback login
- rejected callbacks
- first-login linking
- auto-provisioning rules
- denial rules

### 2. SCIM

Write targeted tests for:

- bearer token authentication
- user list/create/show/replace/patch
- group list/create/show/patch/delete
- error envelope behavior

### 3. Operations

Write targeted tests for:

- metadata refresh
- reconciliation
- emergency recovery

The package itself uses this same testing shape. Its own tests are a
good reference for expected behavior.

## Troubleshooting

### Users can reach the chooser but login fails

Check:

- provider is enabled
- provider scheme matches the route being used
- principal resolver bindings are correct
- provider credentials, authority, and issuer settings are correct

### Callback fails after provider authentication

Check:

- callback route is reachable
- route naming matches your configured callback route
- OIDC issuer and JWKS settings
- SAML signing and metadata settings
- session state and nonce behavior in your middleware stack

### SCIM requests return unauthorized

Check:

- provider has `scim_enabled = true`
- the SCIM bearer token was rotated into the provider record
- your SCIM route middleware stack is not stripping auth headers

### Principals are not linking as expected

Check your `PrincipalResolverInterface` implementation:

- `findPrincipalByEmail`
- `canLinkPrincipal`
- `provisionPrincipal`
- `principalReference`
- `canSignIn`

Most application-specific login issues belong there rather than inside
the package core.

### Provider management works but app UI still feels package-shaped

Use package records and `SsoManager` in your UI layer, not package
models. The package vocabulary is intentionally generic; your UI can
translate it to domain-specific copy such as “organization” or “user”.

## Recommended Consumer Rules

For the cleanest package boundary:

- use `SsoManager` for normal reads and writes
- treat package models as internal
- do not create parallel provider or external identity models
- keep your business rules in the contract implementations
- keep protocol and persistence concerns in the package

If you follow that split, consumers can integrate the package deeply
without having package persistence details leak across the application.
