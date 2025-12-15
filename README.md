# Symfony with ZITADEL

[Symfony](https://symfony.com/) is a set of reusable PHP components and a PHP framework for web projects. It provides a robust set of features for web applications, making it one of the most popular choices for building server-side applications. In a modern setup, your Symfony application manages both your application's frontend and backend logic through server-side routes and controllers.

To secure such an application, you need a reliable way to handle user logins. For the Symfony ecosystem, [Symfony Security](https://symfony.com/doc/current/security.html) is the standard and recommended component for authentication. Think of it as a flexible security guard for your app. This guide demonstrates how to use Symfony Security with a custom authenticator to implement a secure login with ZITADEL.

We'll be using the **OpenID Connect (OIDC)** protocol with the **Authorization Code Flow + PKCE**. This is the industry-best practice for security, ensuring that the login process is safe from start to finish. You can learn more in our [guide to OAuth 2.0 recommended flows](https://zitadel.com/docs/guides/integrate/login/oidc/oauth-recommended-flows).

This example uses **Symfony Security**, the standard for Symfony authentication. While ZITADEL doesn't offer a specific SDK, Symfony Security is highly modular. It works with a custom authenticator that handles the communication with ZITADEL. Under the hood, this example uses the powerful OIDC standard to manage the secure PKCE flow.

Check out our Example Application to see it in action.

## Example Application

The example repository includes a complete Symfony application, ready to run, that demonstrates how to integrate ZITADEL for user authentication.

This example application showcases a typical web app authentication pattern: users start on a public landing page, click a login button to authenticate with ZITADEL, and are then redirected to a protected profile page displaying their user information. The app also includes secure logout functionality that clears the session and redirects users back to ZITADEL's logout endpoint. All protected routes are automatically secured using Symfony Security firewall configuration, ensuring only authenticated users can access sensitive areas of your application.

### Prerequisites

Before you begin, ensure you have the following:

#### System Requirements

- PHP 8.3 or later
- Composer package manager

#### Account Setup

You'll need a ZITADEL account and application configured. Follow the [ZITADEL documentation on creating applications](https://zitadel.com/docs/guides/integrate/login/oidc/web-app) to set up your account and create a Web application with Authorization Code + PKCE flow.

> **Important:** Configure the following URLs in your ZITADEL application settings:
>
> - **Redirect URIs:** Add `http://localhost:3000/auth/callback` (for development)
> - **Post Logout Redirect URIs:** Add `http://localhost:3000/auth/logout/callback` (for development)
>
> These URLs must exactly match what your Symfony application uses. For production, add your production URLs.

### Configuration

To run the application, you first need to copy the `.env.example` file to a new file named `.env` and fill in your ZITADEL application credentials.

```dotenv
# Secret key used to cryptographically sign session cookies and CSRF tokens.
# MUST be a long, random string. Generate a secure key using:
# php -r "echo bin2hex(random_bytes(32));"
APP_SECRET="your-app-secret-key"

# The base URL of your application. Used for generating absolute URLs.
# In development: http://localhost:3000
# In production: https://yourdomain.com
SERVER_URL="http://localhost:3000"

# Port number where your PHP server will listen for incoming HTTP requests.
# Change this if port 3000 is already in use on your system.
SERVER_PORT=3000

# Your ZITADEL instance domain URL. Found in your ZITADEL console under
# instance settings. Include the full https:// URL.
# Example: https://my-company-abc123.zitadel.cloud
ZITADEL_DOMAIN="https://your-zitadel-domain"

# Application Client ID from your ZITADEL application settings. This unique
# identifier tells ZITADEL which application is making the authentication
# request.
ZITADEL_CLIENT_ID="your-client-id"

# While the Authorization Code Flow with PKCE for public clients
# does not strictly require a client secret for OIDC specification compliance,
# Symfony Security will still require a value for its internal configuration.
# Therefore, please provide a randomly generated string here.
# You can generate a secure key using:
# php -r "echo bin2hex(random_bytes(32));"
ZITADEL_CLIENT_SECRET="your-randomly-generated-client-secret"

# URL where users are redirected after logout. This should match a Post Logout
# Redirect URI configured in your ZITADEL application settings.
ZITADEL_POST_LOGOUT_URL="http://localhost:3000/auth/logout/callback"
```

### Installation and Running

Follow these steps to get the application running:

```bash
# 1. Clone the repository
git clone git@github.com:zitadel/example-auth-symfony.git

cd example-auth-symfony

# 2. Install the project dependencies
composer install

# 3. Start the development server
composer run dev
```

The application will now be running at `http://localhost:3000`.

## Key Features

### PKCE Authentication Flow

The application implements the secure Authorization Code Flow with PKCE (Proof Key for Code Exchange), which is the recommended approach for modern web applications.

### Session Management

Built-in session management with Symfony Security handles user authentication state across your application, with automatic token refresh and secure session storage.

### Route Protection

Protected routes automatically redirect unauthenticated users to the login flow, ensuring sensitive areas of your application remain secure.

### Logout Flow

Complete logout implementation that properly terminates both the local session and the ZITADEL session, with proper redirect handling.

## TODOs

### 1. Security headers (Symfony middleware)

**Not enabled.** Consider adding security headers in your Symfony application using the NelmioSecurityBundle:

```bash
composer require nelmio/security-bundle
```

Configure in `config/packages/nelmio_security.yaml`:

```yaml
nelmio_security:
    content_security_policy:
        default-src: "'self'"
        script-src: "'self' 'unsafe-eval' 'unsafe-inline'"
    frame_options:
        enabled: true
```

At minimum, configure:

- `Content-Security-Policy` (CSP)
- `X-Frame-Options` / `frame-ancestors`
- `Referrer-Policy`
- `Permissions-Policy`

## Resources

- **Symfony Documentation:** <https://symfony.com/doc>
- **Symfony Security Documentation:** <https://symfony.com/doc/current/security.html>
- **ZITADEL Documentation:** <https://zitadel.com/docs>
