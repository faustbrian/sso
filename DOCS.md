## `cline/sso` Implementation Guide

This guide is for developers integrating `cline/sso` into a Laravel
application.

It is intentionally implementation-first:

1. understand the package vocabulary
2. install the package
3. configure your app models
4. bind the required contracts
5. create a provider
6. send users through the browser SSO flow
7. optionally add SAML and SCIM

If you want package terminology only, read
[`TERMINOLOGY.md`](TERMINOLOGY.md). If you want to make the package work
in your app, start here.

---

## 1. What This Package Actually Owns

`cline/sso` owns the SSO subsystem itself:

- provider persistence
- external identity persistence
- browser SSO routes
- OIDC flow
- SAML flow
- SCIM HTTP surface
- metadata import and refresh
- validation and recovery commands

Your application still owns application-specific policy:

- what model acts as the `owner`
- what model acts as the `principal`
- how an external identity resolves to a local principal
- whether a principal may link or sign in
- how SCIM should create, update, or remove local records
- where audit events should be written

That split is the core integration model:

- package owns protocol and persistence
- app owns business rules

---

## 2. Terminology You Must Understand

The package uses four core terms:

- `owner`
  The local boundary that owns an SSO provider configuration.
- `provider`
  The upstream SSO or IdP configuration.
- `subject`
  The external identity asserted by the provider.
- `principal`
  The local identity that subject maps to in your app.

In a typical B2B Laravel app:

- `owner` usually maps to `Organization`, `Workspace`, or `Account`
- `principal` usually maps to `User`, `Member`, or `Admin`

In `/Users/brian/Developer/api`, the mapping is:

- `owner` = `Organization`
- `provider` = one organization-owned SSO configuration
- `subject` = Azure / Okta / SAML external identity
- `principal` = local `User`

If this mapping is not clear yet, stop and read
[`TERMINOLOGY.md`](TERMINOLOGY.md) first.

---

## 3. Minimum Working Integration

If your goal is to get from zero to one working login flow, do this in
order:

1. install the package
2. run the package migrations
3. configure `owner` and `principal`
4. bind the required contracts
5. create one OIDC provider
6. send users to the package SSO route
7. verify the callback signs a principal in

Do not start with SCIM. Do not start with SAML. Get one OIDC provider
working first.

---

## 4. Installation

Install the package:

```bash
composer require cline/sso
```

Publish the configuration if you want to edit it in your app:

```bash
php artisan vendor:publish --tag=sso-config
```

Publish the migrations if you want them copied into your application:

```bash
php artisan vendor:publish --tag=sso-migrations
```

Run your migrations:

```bash
php artisan migrate
```

If you are happy letting the package load its own migrations, publishing
them is optional.

---

## 5. The Config You Must Set

The package can boot without much configuration, but a real integration
must set these values in `config/sso.php`.

### `models.owner`

This is the class that owns provider configuration.

Example:

```php
'models' => [
    'owner' => App\Models\Organization::class,
    'principal' => App\Models\User::class,
],
```

### `models.principal`

This is the local identity model the package links subjects to.

Example:

```php
'models' => [
    'owner' => App\Models\Organization::class,
    'principal' => App\Models\User::class,
],
```

### `guard`

This is the Laravel guard used when the package signs principals in.

Typical value:

```php
'guard' => 'web',
```

### `login.redirect_to` or `login.redirect_route_name`

This controls where successful logins go.

Use one of:

```php
'login' => [
    'redirect_to' => '/',
    'redirect_route_name' => null,
],
```

or:

```php
'login' => [
    'redirect_to' => '/',
    'redirect_route_name' => 'dashboard',
],
```

### `routes`

These control whether package browser routes and SCIM routes are
registered and what prefixes they use.

Typical defaults:

```php
'routes' => [
    'enabled' => true,
    'prefix' => 'sso',
    'name_prefix' => 'sso.',
    'scim_enabled' => true,
    'scim_prefix' => 'scim/v2',
    'scim_name_prefix' => 'sso.scim.',
],
```

If you want the package routes, leave them enabled.

---

## 6. Contracts Your App Must Bind

This package is not usable without consumer bindings. These are the
required integration points.

### `PrincipalResolverInterface`

This is the most important contract.

Your implementation decides:

- how to find a principal by email
- how to find a principal from an existing external identity
- whether the package may link a subject to a principal
- whether the package may provision a new principal
- how to produce a stable principal reference
- whether a resolved principal may sign in
- what should happen after login

If you do not implement this well, your SSO behavior will be wrong even
if the protocol layer is correct.

### `AuditSinkInterface`

This receives package audit events.

Use it if you want:

- database activity logs
- external audit systems
- structured internal event logging

### `ScimUserAdapterInterface`

This is required if you enable SCIM and want SCIM `Users` to mutate your
application.

It defines how the package should:

- list local principals as SCIM users
- create a local principal
- replace a local principal
- patch a local principal
- resolve a local principal by SCIM identifier

### `ScimGroupAdapterInterface`

This is required if you want SCIM `Groups`.

It defines how the package should:

- list SCIM-manageable groups
- create groups
- patch groups
- delete groups
- resolve groups by SCIM identifier

### `ScimReconcilerInterface`

This is used by the package’s reconciliation command and scheduled sync
work.

Use it if your app needs to reconcile memberships or role assignments
outside of request-time SCIM updates.

### Example bindings

Bind the contracts in a service provider:

```php
use App\Support\Sso\ActivityAuditSink;
use App\Support\Sso\PrincipalResolver;
use App\Support\Sso\ScimGroupAdapter;
use App\Support\Sso\ScimReconciler;
use App\Support\Sso\ScimUserAdapter;
use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Contracts\PrincipalResolverInterface;
use Cline\SSO\Contracts\ScimGroupAdapterInterface;
use Cline\SSO\Contracts\ScimReconcilerInterface;
use Cline\SSO\Contracts\ScimUserAdapterInterface;

$this->app->singleton(
    PrincipalResolverInterface::class,
    PrincipalResolver::class,
);

$this->app->singleton(
    AuditSinkInterface::class,
    ActivityAuditSink::class,
);

$this->app->singleton(
    ScimUserAdapterInterface::class,
    ScimUserAdapter::class,
);

$this->app->singleton(
    ScimGroupAdapterInterface::class,
    ScimGroupAdapter::class,
);

$this->app->singleton(
    ScimReconcilerInterface::class,
    ScimReconciler::class,
);
```

---

## 7. The Main Package API You Should Use

The normal consumer-facing API is:

```php
Cline\SSO\SsoManager
```

Use `SsoManager` for normal package operations:

- list login providers
- search providers
- create a provider
- update a provider
- delete a provider
- import metadata
- validate a provider
- refresh metadata
- look up or persist external identities

Use repository interfaces only if you are intentionally replacing
package persistence behavior.

If you are building app code and asking “should I use the manager or the
repository?”, the answer is almost always the manager.

---

## 8. Creating Your First OIDC Provider

After installing the package and binding the contracts, create one OIDC
provider.

You can do that through your own admin UI or directly through
`SsoManager`.

Typical OIDC fields:

- `driver` = `oidc`
- `scheme`
- `display_name`
- `authority`
- `client_id`
- `client_secret`
- `valid_issuer`
- `validate_issuer`
- `enabled`

Example:

```php
use Cline\SSO\SsoManager;

public function __invoke(SsoManager $sso): void
{
    $sso->createProvider([
        'owner_id' => 'org_123',
        'driver' => 'oidc',
        'scheme' => 'acme-entra',
        'display_name' => 'Acme Entra ID',
        'authority' => 'https://login.microsoftonline.com/acme/v2.0',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'valid_issuer' => 'https://login.microsoftonline.com/acme/v2.0',
        'validate_issuer' => true,
        'enabled' => true,
    ]);
}
```

Your actual owner identifier and admin workflow will depend on your app.

The important thing is:

- the provider belongs to one `owner`
- the provider uses `oidc`
- the provider is enabled

---

## 9. Browser Login Flow

Once a provider exists, the package browser flow is:

1. user visits the package SSO entry route
2. user chooses a provider
3. package redirects to the upstream IdP
4. upstream IdP redirects back to the package callback
5. package validates the response
6. package resolves or provisions a local principal through your
   `PrincipalResolverInterface`
7. package signs the principal in with the configured guard
8. package redirects to the configured post-login destination

### Default routes

If package web routes are enabled, the browser entrypoint is under the
configured SSO prefix.

With default config:

- entrypoint: `/sso`
- redirect: `/sso/{scheme}/redirect`
- callback: `/sso/{scheme}/callback`

### How to link to the entrypoint

Use the package route name:

```php
route('sso.index')
```

Or whatever you configured via `routes.name_prefix` and
`routes.index_name`.

### What your app must do during login

During login, the package needs your principal resolver to answer these
questions:

- Is there already a linked principal for this subject?
- If not, can the package find one by email?
- If it finds one, may the package link it?
- If none exists, may the package provision one?
- If a principal is found or provisioned, may that principal sign in?

If those answers are wrong, your login behavior will be wrong.

---

## 10. OIDC Integration Notes

Use `oidc` when the upstream provider supports OpenID Connect.

The package handles:

- discovery documents
- JWKS loading and caching
- ID token validation
- issuer validation
- audience and authorized party checks
- nonce validation
- timing validation

The application does not need to implement JWT or discovery logic.

What the application still decides:

- whether the resolved principal may link
- whether a principal may sign in
- how local provisioning works

Recommended first provider to integrate:

- Microsoft Entra ID / Azure AD
- Okta OIDC
- Auth0 OIDC

Get one OIDC provider working before attempting SAML.

---

## 11. SAML Integration Notes

Use `saml2` when the upstream provider is SAML-based.

The package handles:

- SAML metadata parsing
- assertion decoding
- signature validation
- issuer, audience, destination, and recipient checks
- optional signed AuthnRequests
- certificate rollover support

The application still decides principal resolution and authorization in
the same way as OIDC.

Recommended approach:

1. make OIDC work first
2. add one SAML provider
3. verify the callback and linking path
4. then add metadata import and refresh automation

---

## 12. SCIM Integration Notes

SCIM is optional.

Do not implement SCIM until browser login works.

### What the package owns

The package owns the SCIM HTTP protocol layer:

- route registration
- request validation
- SCIM error responses
- `Users`
- `Groups`
- `Schemas`
- `ResourceTypes`
- `ServiceProviderConfig`

### What your app must provide

Your app must tell the package how SCIM changes affect your local data.

That is what the SCIM adapters are for:

- `ScimUserAdapterInterface`
- `ScimGroupAdapterInterface`
- `ScimReconcilerInterface`

### Recommended rollout order

1. support SCIM `Users`
2. verify create, replace, and patch behavior
3. support SCIM `Groups` if your app needs them
4. add reconciliation if your app needs periodic drift correction

---

## 13. Metadata Import, Validation, And Refresh

The package can import and refresh provider metadata.

Use these capabilities after the login flow itself is already working.

Typical use cases:

- import OIDC discovery information
- import SAML metadata
- validate a provider before enabling it
- periodically refresh metadata and keys

This belongs to the package because it is protocol infrastructure, not
application business logic.

What your app usually does with it:

- expose admin actions to import or validate providers
- show health information
- surface refresh failures

---

## 14. Package Commands

The package includes operational commands for:

- metadata refresh
- SCIM reconciliation
- recovery and break-glass access handling

These commands are part of the package’s operational layer. Your app
should generally call them or schedule them, not reimplement them.

Typical production setup:

- schedule metadata refresh
- schedule reconciliation if your app uses SCIM group or membership sync
- keep recovery commands documented for operators

---

## 15. Suggested Implementation Order

If you are integrating into a real app, follow this order:

### Phase 1: Minimal OIDC login

1. install the package
2. run migrations
3. configure `owner`, `principal`, and `guard`
4. bind `PrincipalResolverInterface`
5. bind `AuditSinkInterface`
6. create one OIDC provider
7. route users to the package SSO entrypoint
8. verify login works

### Phase 2: Provider administration

1. build admin CRUD around `SsoManager`
2. add validation
3. add metadata import
4. add provider health display

### Phase 3: SAML

1. add one SAML provider
2. verify metadata import
3. verify callback and principal resolution

### Phase 4: SCIM

1. implement `ScimUserAdapterInterface`
2. test SCIM `Users`
3. implement `ScimGroupAdapterInterface` if needed
4. implement `ScimReconcilerInterface` if needed

This ordering keeps the integration manageable and avoids debugging too
many moving parts at once.

---

## 16. Typical App Architecture

A normal consumer app should look like this:

- package owns SSO persistence
- package owns routes
- package owns protocol handling
- app binds contract implementations
- app builds its own admin UI using `SsoManager`

What your app should not do:

- reimplement OIDC token validation
- reimplement SAML validation
- create parallel provider persistence models
- bypass the package with direct database writes unless you are doing
  something truly unusual

The normal extension points are contracts and `SsoManager`, not package
internals.

---

## 17. Example Mapping For A Real App

Here is the concrete mapping for a typical organization-based app:

- `owner` = `Organization`
- `principal` = `User`

That means:

- one organization owns one or more providers
- one provider can assert many subjects
- each subject can be linked to one local user

Your principal resolver then decides:

- how an OIDC email maps to a `User`
- how a SAML subject maps to a `User`
- whether an existing `User` may be linked
- whether a `User` may sign in to that organization’s provider

That is the intended package boundary.

---

## 18. Troubleshooting

### “The package installs, but login still does not work”

Usually one of these is missing:

- your `owner` model config
- your `principal` model config
- your `PrincipalResolverInterface` binding
- an enabled provider record

### “The callback succeeds externally, but no one gets logged in”

Usually the resolver or sign-in policy is refusing the principal:

- principal not found
- linking denied
- provisioning denied
- sign-in denied

### “SCIM endpoints exist, but nothing changes in the app”

That usually means you are still using null adapters:

- `NullScimUserAdapter`
- `NullScimGroupAdapter`
- `NullScimReconciler`

Bind real implementations.

### “I don’t know whether to use the manager or the repositories”

Use `SsoManager` unless you are deliberately replacing package
persistence.

### “Do I need to rename my app models to Owner and Principal?”

No.

Configure your real model classes in `config/sso.php`. The package
vocabulary exists to keep the SSO subsystem unambiguous, not to force
your app to rename domain models.

---

## 19. What To Read Next

If you are still at the beginning:

- read [`TERMINOLOGY.md`](TERMINOLOGY.md)
- then implement the minimal OIDC flow from this guide

If OIDC already works and you are extending the subsystem:

- use this guide’s SAML and SCIM sections
- then read the package config comments in [`config/sso.php`](config/sso.php)

If you are building administration around the package:

- use `SsoManager`
- keep protocol behavior in the package
- keep business rules in your application contracts
