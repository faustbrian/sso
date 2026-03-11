<?php declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Authentication Guard
    |--------------------------------------------------------------------------
    |
    | This guard is used when authenticating SSO users within your
    | application. It should match the guard that manages the user provider
    | and session behavior for the users signing in through SSO.
    |
    */

    'guard' => 'web',

    /*
    |--------------------------------------------------------------------------
    | Primary Key Type
    |--------------------------------------------------------------------------
    |
    | This value defines the default primary key type used by SSO-related
    | models and foreign key mappings. Override this when your application
    | uses UUIDs, ULIDs, or another key strategy instead of integer IDs.
    |
    */

    'primary_key_type' => env('SSO_PRIMARY_KEY_TYPE', 'id'),

    /*
    |--------------------------------------------------------------------------
    | Login Redirects
    |--------------------------------------------------------------------------
    |
    | These options control where users are sent after a successful SSO
    | login. You may provide either a direct path or a named route,
    | depending on how you want post-authentication navigation to behave.
    |
    */

    'login' => [
        /*
        |--------------------------------------------------------------------------
        | Redirect Path
        |--------------------------------------------------------------------------
        |
        | This path is used as the default post-login destination when no
        | named route has been configured. It should be a valid application
        | path that authenticated users can access after signing in.
        |
        */

        'redirect_to' => '/',

        /*
        |--------------------------------------------------------------------------
        | Redirect Route Name
        |--------------------------------------------------------------------------
        |
        | This optional named route takes precedence over the redirect path
        | when provided. Set this to a route name if you prefer Laravel to
        | generate the destination URL from your route definitions.
        |
        */

        'redirect_route_name' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Durations
    |--------------------------------------------------------------------------
    |
    | These values define how long SSO discovery documents, JSON Web Key
    | Sets, and provider metadata should remain cached. Tuning these
    | durations lets you balance freshness against outbound network usage.
    |
    */

    'cache' => [
        /*
        |--------------------------------------------------------------------------
        | Discovery TTL
        |--------------------------------------------------------------------------
        |
        | This value determines how many seconds OpenID Connect discovery
        | documents are cached before they must be fetched again from the
        | identity provider.
        |
        */

        'discovery_ttl' => 600,

        /*
        |--------------------------------------------------------------------------
        | JWKS TTL
        |--------------------------------------------------------------------------
        |
        | This value determines how many seconds JSON Web Key Sets are
        | cached before the signing keys are refreshed from the identity
        | provider.
        |
        */

        'jwks_ttl' => 600,

        /*
        |--------------------------------------------------------------------------
        | Metadata TTL
        |--------------------------------------------------------------------------
        |
        | This value determines how many seconds generic provider metadata
        | is cached before the package refreshes it. Increase this if your
        | provider metadata changes infrequently.
        |
        */

        'metadata_ttl' => 3600,
    ],

    /*
    |--------------------------------------------------------------------------
    | Strategy Drivers
    |--------------------------------------------------------------------------
    |
    | This section maps SSO driver names to the strategy classes that
    | implement them. Each configured provider references one of these
    | keys to determine which authentication strategy should be used.
    |
    */

    'drivers' => [
        /*
        |--------------------------------------------------------------------------
        | OIDC Strategy
        |--------------------------------------------------------------------------
        |
        | This strategy class handles OpenID Connect providers. Use this
        | driver for providers that support the OIDC discovery, token, and
        | user information flows.
        |
        */

        'oidc' => \Cline\SSO\Drivers\Oidc\OidcStrategy::class,

        /*
        |--------------------------------------------------------------------------
        | SAML 2 Strategy
        |--------------------------------------------------------------------------
        |
        | This strategy class handles SAML 2.0 providers. Use this driver
        | when integrating with identity providers that expose SAML-based
        | login and assertion workflows.
        |
        */

        'saml2' => \Cline\SSO\Drivers\Saml\SamlStrategy::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Route Configuration
    |--------------------------------------------------------------------------
    |
    | These options control the HTTP routes registered by the package for
    | browser-based SSO flows and SCIM endpoints. Adjust the prefixes,
    | middleware, and route names here to fit your application's routing
    | conventions.
    |
    */

    'routes' => [
        /*
        |--------------------------------------------------------------------------
        | Route Registration
        |--------------------------------------------------------------------------
        |
        | This value determines whether the package should register its web
        | routes automatically. Disable this if you want to define or mount
        | the routes yourself.
        |
        */

        'enabled' => true,

        /*
        |--------------------------------------------------------------------------
        | Web Route Middleware
        |--------------------------------------------------------------------------
        |
        | These middleware aliases are applied to the package's browser-
        | based SSO routes. Add any session, CSRF, or owner middleware
        | needed before users begin the authentication flow.
        |
        */

        'middleware' => [
            /*
            |--------------------------------------------------------------------------
            | Web Middleware Alias
            |--------------------------------------------------------------------------
            |
            | This middleware enables stateful browser behavior for SSO web
            | routes, including sessions, cookies, and CSRF protection.
            |
            */

            'web',
        ],

        /*
        |--------------------------------------------------------------------------
        | Route Prefix
        |--------------------------------------------------------------------------
        |
        | This URI prefix is applied to the package's browser-based SSO
        | routes. Change it if you want the login and callback endpoints to
        | live under a different path segment.
        |
        */

        'prefix' => 'sso',

        /*
        |--------------------------------------------------------------------------
        | Route Name Prefix
        |--------------------------------------------------------------------------
        |
        | This prefix is prepended to the names of routes registered by the
        | package. It helps keep generated route names organized and avoids
        | collisions with routes from the rest of your application.
        |
        */

        'name_prefix' => 'sso.',

        /*
        |--------------------------------------------------------------------------
        | Index Route Name
        |--------------------------------------------------------------------------
        |
        | This is the route name assigned to the package's SSO index
        | endpoint. Use it when linking to the provider selection or entry
        | point for starting an authentication flow.
        |
        */

        'index_name' => 'sso.index',

        /*
        |--------------------------------------------------------------------------
        | Callback Route Name
        |--------------------------------------------------------------------------
        |
        | This is the route name assigned to the authentication callback
        | endpoint. Providers will redirect users here after completing the
        | external authentication step.
        |
        */

        'callback_name' => 'sso.callback',

        /*
        |--------------------------------------------------------------------------
        | SCIM Route Registration
        |--------------------------------------------------------------------------
        |
        | This value determines whether SCIM routes should be registered in
        | addition to the browser-based SSO routes. Disable this if your
        | application does not expose SCIM provisioning endpoints.
        |
        */

        'scim_enabled' => true,

        /*
        |--------------------------------------------------------------------------
        | SCIM Route Prefix
        |--------------------------------------------------------------------------
        |
        | This URI prefix is applied to the package's SCIM routes. Adjust
        | it if your provisioning endpoints need to be mounted under a
        | different path structure.
        |
        */

        'scim_prefix' => 'scim/v2',

        /*
        |--------------------------------------------------------------------------
        | SCIM Route Name Prefix
        |--------------------------------------------------------------------------
        |
        | This prefix is prepended to the names of the package's SCIM
        | routes. Use it to align SCIM route naming with your
        | application's conventions or to avoid collisions.
        |
        */

        'scim_name_prefix' => 'sso.scim.',

        /*
        |--------------------------------------------------------------------------
        | SCIM Route Middleware
        |--------------------------------------------------------------------------
        |
        | These middleware aliases are applied to SCIM provisioning routes.
        | Use them to enforce authentication, rate limiting, or custom
        | request validation around SCIM traffic.
        |
        */

        'scim_middleware' => [
            /*
            |--------------------------------------------------------------------------
            | API Middleware Alias
            |--------------------------------------------------------------------------
            |
            | This middleware applies the application's API stack to SCIM
            | routes, such as stateless handling, throttling, or request
            | formatting conventions defined for API endpoints.
            |
            */

            'api',

            /*
            |--------------------------------------------------------------------------
            | SCIM Middleware Alias
            |--------------------------------------------------------------------------
            |
            | This middleware enforces package-specific SCIM behavior such
            | as authentication, authorization, or request normalization for
            | provisioning endpoints.
            |
            */

            'sso.scim',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Repository Implementations
    |--------------------------------------------------------------------------
    |
    | These classes are responsible for persisting and retrieving SSO
    | provider records and external identity mappings. Replace them if you
    | need to store this data using a custom persistence layer.
    |
    */

    'repositories' => [
        /*
        |--------------------------------------------------------------------------
        | Provider Repository
        |--------------------------------------------------------------------------
        |
        | This repository manages storage and retrieval of configured SSO
        | providers. The class should implement the package contract for
        | provider persistence.
        |
        */

        'provider' => \Cline\SSO\Persistence\EloquentProviderRepository::class,

        /*
        |--------------------------------------------------------------------------
        | External Identity Repository
        |--------------------------------------------------------------------------
        |
        | This repository manages the link between local principals and their
        | external provider identities. Replace it if you need custom
        | lookup or persistence behavior for identity mappings.
        |
        */

        'external_identity' => \Cline\SSO\Persistence\EloquentExternalIdentityRepository::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Model Classes
    |--------------------------------------------------------------------------
    |
    | These model classes are used when the package needs to reference
    | your application-level owner and principal records. The package's
    | own persistence models remain internal implementation details.
    |
    */

    'models' => [
        /*
        |--------------------------------------------------------------------------
        | Owner Model
        |--------------------------------------------------------------------------
        |
        | This model represents the owner associated with an SSO provider.
        | Set this to your application's owner or account-boundary model class
        | when using owner-scoped SSO.
        |
        */

        'owner' => env('SSO_OWNER_MODEL', 'App\\Models\\Owner'),

        /*
        |--------------------------------------------------------------------------
        | Principal Model
        |--------------------------------------------------------------------------
        |
        | This model represents the authenticatable principal linked to external
        | identities. Set this to the model class used by your application
        | for principals signing in through SSO.
        |
        */

        'principal' => env('SSO_PRINCIPAL_MODEL', 'App\\Models\\Principal'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Table Names
    |--------------------------------------------------------------------------
    |
    | These table names are used by the package's default Eloquent models
    | and repositories. Customize them if you need to align with an
    | existing schema or naming convention in your application.
    |
    */

    'table_names' => [
        /*
        |--------------------------------------------------------------------------
        | Providers Table
        |--------------------------------------------------------------------------
        |
        | This table stores the configured SSO providers for your
        | application. Each record contains the strategy, credentials, and
        | settings needed to communicate with a provider.
        |
        */

        'providers' => 'sso_providers',

        /*
        |--------------------------------------------------------------------------
        | External Identities Table
        |--------------------------------------------------------------------------
        |
        | This table stores the mappings between local principals and their
        | external identities. It allows the package to resolve returning
        | principals from provider-specific identifiers.
        |
        */

        'external_identities' => 'external_identities',
    ],

    /*
    |--------------------------------------------------------------------------
    | Foreign Key Mapping
    |--------------------------------------------------------------------------
    |
    | These settings define how the package references your owner
    | and principal models from its own tables. Configure the column names,
    | owner keys, and key types to match your application's schema.
    |
    */

    'foreign_keys' => [
        /*
        |--------------------------------------------------------------------------
        | Owner Foreign Key
        |--------------------------------------------------------------------------
        |
        | These options configure how package records reference the
        | owner model. They should match the foreign key column,
        | owner key name, and identifier type used in your schema.
        |
        */

        'owner' => [
            /*
            |--------------------------------------------------------------------------
            | Owner Foreign Key Column
            |--------------------------------------------------------------------------
            |
            | This column stores the owner identifier on package-
            | managed records. It should match the foreign key column name
            | used by your application's database schema.
            |
            */

            'column' => 'tenant_id',

            /*
            |--------------------------------------------------------------------------
            | Owner Key
            |--------------------------------------------------------------------------
            |
            | This value defines which column on the owner model is
            | referenced by the foreign key. Set it to the primary or unique
            | key used when linking SSO records to provider owners.
            |
            */

            'owner_key' => env('SSO_OWNER_KEY_NAME', 'id'),

            /*
            |--------------------------------------------------------------------------
            | Owner Key Type
            |--------------------------------------------------------------------------
            |
            | This value defines the identifier type used by the
            | owner relationship. It should reflect whether the owner
            | key is an integer, UUID, ULID, or another key format.
            |
            */

            'type' => env('SSO_OWNER_KEY_TYPE', env('SSO_PRIMARY_KEY_TYPE', 'id')),
        ],

        /*
        |--------------------------------------------------------------------------
        | Principal Foreign Key
        |--------------------------------------------------------------------------
        |
        | These options configure how package records reference the principal
        | model. They should match the foreign key column, owner key name,
        | and identifier type used by your application's principal table.
        |
        */

        'principal' => [
            /*
            |--------------------------------------------------------------------------
            | Principal Foreign Key Column
            |--------------------------------------------------------------------------
            |
            | This column stores the principal identifier on package-managed
            | records. It should align with the foreign key column name used
            | by your external identity and provider relationships.
            |
            */

            'column' => 'user_id',

            /*
            |--------------------------------------------------------------------------
            | Principal Owner Key
            |--------------------------------------------------------------------------
            |
            | This value defines which column on the principal model is
            | referenced by the foreign key. Set it to the primary or unique
            | key used when linking SSO records to principals.
            |
            */

            'owner_key' => env('SSO_PRINCIPAL_KEY_NAME', 'id'),

            /*
            |--------------------------------------------------------------------------
            | Principal Key Type
            |--------------------------------------------------------------------------
            |
            | This value defines the identifier type used by the principal
            | relationship. It should reflect whether the owner key is an
            | integer, UUID, ULID, or another key format.
            |
            */

            'type' => env('SSO_PRINCIPAL_KEY_TYPE', env('SSO_PRIMARY_KEY_TYPE', 'id')),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Morph Key Map
    |--------------------------------------------------------------------------
    |
    | This map lets you define the morph key used for each polymorphic
    | model class referenced by the package. Populate these entries when
    | your related models do not use the default primary key name.
    |
    */

    'morphKeyMap' => [
        /*
        |--------------------------------------------------------------------------
        | Principal Morph Key
        |--------------------------------------------------------------------------
        |
        | Define the morph key column for your principal model when polymorphic
        | relations should reference a key other than the package default.
        |
        */

        // App\Models\Principal::class => 'id',

        /*
        |--------------------------------------------------------------------------
        | Owner Morph Key
        |--------------------------------------------------------------------------
        |
        | Define the morph key column for your owner model when
        | polymorphic relations should reference a key other than the
        | package default.
        |
        */

        // App\Models\Owner::class => 'id',
    ],

    /*
    |--------------------------------------------------------------------------
    | Enforced Morph Key Map
    |--------------------------------------------------------------------------
    |
    | This map allows you to require explicit morph key definitions for
    | specific model classes. Use it when you want the package to enforce
    | known key mappings for polymorphic relationships.
    |
    */

    'enforceMorphKeyMap' => [
        /*
        |--------------------------------------------------------------------------
        | Enforced Principal Morph Key
        |--------------------------------------------------------------------------
        |
        | Define the required morph key column for your principal model when the
        | package should enforce a specific key mapping for polymorphic
        | relationships.
        |
        */

        // App\Models\Principal::class => 'id',

        /*
        |--------------------------------------------------------------------------
        | Enforced Owner Morph Key
        |--------------------------------------------------------------------------
        |
        | Define the required morph key column for your owner model
        | when the package should enforce a specific key mapping for
        | polymorphic relationships.
        |
        */

        // App\Models\Owner::class => 'id',
    ],

    /*
    |--------------------------------------------------------------------------
    | Package Contracts
    |--------------------------------------------------------------------------
    |
    | These classes provide the default implementations for extension
    | points used by the package. Replace any of them with your own
    | implementation to customize resolution, auditing, or SCIM behavior.
    |
    */

    'contracts' => [
        /*
        |--------------------------------------------------------------------------
        | Principal Resolver
        |--------------------------------------------------------------------------
        |
        | This class resolves or provisions a local principal from provider
        | claims during authentication. Replace the null implementation when
        | your application needs custom principal lookup or creation logic.
        |
        */

        'principal_resolver' => \Cline\SSO\Support\NullPrincipalResolver::class,

        /*
        |--------------------------------------------------------------------------
        | Audit Sink
        |--------------------------------------------------------------------------
        |
        | This class receives audit events emitted by the package. Replace
        | the null implementation to record SSO activity to logs, queues, or
        | another audit system.
        |
        */

        'audit_sink' => \Cline\SSO\Support\NullAuditSink::class,

        /*
        |--------------------------------------------------------------------------
        | SCIM User Adapter
        |--------------------------------------------------------------------------
        |
        | This class adapts your application's principal model to the SCIM user
        | representation used by the package. Replace the null
        | implementation when exposing SCIM user provisioning endpoints.
        |
        */

        'scim_user_adapter' => \Cline\SSO\Support\NullScimUserAdapter::class,

        /*
        |--------------------------------------------------------------------------
        | SCIM Group Adapter
        |--------------------------------------------------------------------------
        |
        | This class adapts your application's group or owner data to
        | the SCIM group representation used by the package. Replace the
        | null implementation when exposing SCIM group provisioning.
        |
        */

        'scim_group_adapter' => \Cline\SSO\Support\NullScimGroupAdapter::class,

        /*
        |--------------------------------------------------------------------------
        | SCIM Reconciler
        |--------------------------------------------------------------------------
        |
        | This class coordinates SCIM provisioning updates with your
        | application's domain models. Replace the null implementation when
        | SCIM requests should create, update, or deactivate local records.
        |
        */

        'scim_reconciler' => \Cline\SSO\Support\NullScimReconciler::class,
    ],
];
