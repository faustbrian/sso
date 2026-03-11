<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Single Sign-On</title>
</head>
<body>
    <main>
        <h1>Single Sign-On</h1>

        @if ($errors->has('sso'))
            <p role="alert">{{ $errors->first('sso') }}</p>
        @endif

        @if ($providers === [])
            <p>No SSO providers are currently available.</p>
        @else
            <ul>
                @foreach ($providers as $provider)
                    <li>
                        <a href="{{ route('sso.redirect', ['scheme' => $provider['scheme']]) }}">
                            {{ $provider['display_name'] }}
                        </a>
                    </li>
                @endforeach
            </ul>
        @endif
    </main>
</body>
</html>
