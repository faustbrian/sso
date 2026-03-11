# Terminology

This document defines the package vocabulary used throughout
`cline/sso`.

The package uses different terms for different concerns. They are
deliberately not interchangeable.

## Core terms

- `owner` means the local boundary that owns one or more SSO provider
  configurations
- `provider` means the upstream identity-provider configuration managed
  by the package
- `subject` means the external identity asserted by that provider
- `principal` means the local identity that the package links the
  external subject to

## Why these terms

- `owner` is used instead of `tenant` or `organization` because the
  package should not force a specific tenancy model
- `principal` is used instead of `user` because the linked local
  identity may be a user, member, admin, operator, or another
  authenticatable concept
- `subject` is used because it is the protocol-correct identity term
  for OIDC and SAML assertions

## Owner

An `owner` is the local application boundary that owns provider
configuration.

Typical real-world mappings:

- organization
- workspace
- merchant account
- customer account
- team
- business unit

Important:

- the owner is about configuration ownership
- the owner is not the person signing in
- the package does not require a literal `Owner` model name

## Provider

A `provider` is an upstream identity configuration managed by the
package.

Examples:

- an Azure AD / Entra ID OIDC configuration
- an Okta OIDC configuration
- a customer-specific SAML IdP configuration

A provider typically contains:

- driver
- scheme
- display name
- authority or metadata location
- client credentials
- validation settings
- SCIM settings

## Subject

A `subject` is the external identity asserted by the provider.

Protocol mapping:

- in OIDC this maps closely to the `sub` claim
- in SAML this maps to the assertion subject, commonly the `NameID`

Important:

- the subject belongs to the upstream provider
- the subject is not your local application identifier
- the same local principal may be linked to different subjects across
  different providers

## Principal

A `principal` is the local identity target that the package links the
subject to.

Typical real-world mappings:

- user
- member
- admin
- operator
- backoffice account

Important:

- `principal` is the package term
- your application can still call this model `User`, `Member`, or any
  other domain-appropriate name
- SCIM still uses `User` where the protocol requires it; that does not
  change the package’s core vocabulary

## External identity

An `external identity` is the persisted link between:

- a provider
- an issuer
- a subject
- a local principal

This is the durable mapping the package uses to resolve future sign-ins
without rerunning first-login heuristics.

## Mapping in `api`

In `/Users/brian/Developer/api`, the package terms map like this:

- `owner` -> `Organization`
- `provider` -> an organization-owned SSO configuration
- `subject` -> the external IdP identity from Azure, Okta, or SAML
- `principal` -> local `User`

That means the flow in `api` is:

1. An `Organization` owns one or more SSO `providers`.
2. A provider authenticates someone externally and asserts a `subject`.
3. The package links that subject to a local `User`.
4. SCIM provisions or reconciles local users and groups for that same
   organization/provider relationship.

## Example mappings

### B2B SaaS app

- owner: `Organization`
- provider: `Acme Azure AD`
- subject: the Entra ID subject for Jane Doe
- principal: local `User` record for Jane Doe

### Workspace-based app

- owner: `Workspace`
- provider: `Contoso Okta`
- subject: the Okta subject for Alex
- principal: local workspace member account

### Merchant platform

- owner: `MerchantAccount`
- provider: `Merchant SAML`
- subject: the asserted merchant employee identity
- principal: local backoffice account

## Naming guidance for consumers

Consumers do not need to rename their own application models to match
the package.

Examples:

- your app can keep an `Organization` model and configure it as the
  package owner model
- your app can keep a `User` model and configure it as the package
  principal model
- your app can expose roles, groups, and memberships using its own
  domain language

The package terminology exists to keep the SSO subsystem unambiguous,
not to force application renames.
