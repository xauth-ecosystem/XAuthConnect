# XAuthConnect

[![Poggit CI](https://poggit.pmmp.io/ci.shield/newlandpe/XAuthConnect/XAuthConnect)](https://poggit.pmmp.io/ci/newlandpe/XAuthConnect/XAuthConnect)

A powerful extension for the XAuth plugin that provides an OAuth 2.0-like authentication layer, allowing external web applications to securely access player data.

## Features

- **OAuth 2.0 Flow:** Implements a standard authorization code flow for secure authentication.
- **Web Server Integration:** Runs a built-in, configurable web server to handle API requests.
- **Registered Clients:** Securely manage which external applications can connect, with unique client IDs and secrets.
- **Rate Limiting:** Protects your server from abuse with configurable request limits per client.
- **Extensible Scopes:** Allows other plugins to register their own data scopes, making player data available via the API.
- **Database Support:** Supports SQLite and MySQL for storing authorization codes and tokens.

## Dependencies

- **[XAuth](https://github.com/newlandpe/XAuth):** This plugin is an extension of XAuth and requires it to be installed and active.
- **[PMMP WebServer](https://github.com/Hebbinkpro/pmmp-webserver):** The web server functionality is provided by this library, which is bundled with the plugin.

## Installation

1. Download the latest stable version of XAuthConnect from [Poggit CI](https://poggit.pmmp.io/ci/newlandpe/XAuthConnect/XAuthConnect).
2. Place the `XAuthConnect.phar` file into the `plugins/` folder of your PocketMine-MP server.
3. Restart your server. The plugin will generate its configuration files.

## Configuration

The plugin generates a `config.yml` file in `plugin_data/XAuthConnect/` upon first run. 

### Web Integration (`web-integration`)

- `enabled`: (true/false) Master switch to enable or disable the web server.
- `server-port`: The port the web server will listen on (e.g., 8443).
- `base-url`: The public base URL of your server (e.g., "https://mc.yourdomain.com").
- `code-timeout`: How long (in seconds) an authorization code is valid.

### SSL/TLS (`ssl`)

- `cert-folder`: The folder within `plugin_data/XAuthConnect/` containing your SSL certificate files (`.pem`, `.cert`).
- `passphrase`: The passphrase for your private key, if it is encrypted.

### Registered Clients (`registered-clients`)

This is where you define the applications that can connect to your server.

```yaml
registered-clients:
  forum:
    client-id: "forum_client_123"
    client-secret: "super_secret_key"
    name: "Community Forum"
    redirect-uris:
      - "https://forum.example.com/auth/callback"
    allowed-scopes:
      - "profile:nickname"
      - "profile:uuid"
    rate-limits:
      requests-per-minute: 60
```

- `client-id`: A unique identifier for your application.
- `client-secret`: A secret key known only to your application and the server.
- `name`: A display name for the application, shown on the login page.
- `redirect-uris`: A list of valid URLs where the user can be redirected after authorization.
- `allowed-scopes`: The data scopes this client is allowed to request.
- `rate-limits`: The maximum number of requests per minute this client can make.

### Database (`database`)

- `type`: The database type to use (`sqlite` or `mysql`).
- `worker-limit`: Number of threads for database queries.
- `sqlite`: Contains the `file` name for the SQLite database.
- `mysql`: Contains connection details (`host`, `user`, `password`, `database`, `port`) for MySQL.

## API Endpoints

XAuthConnect provides a set of HTTP endpoints to handle the authentication flow.

### `GET /xauth/authorize`

Starts the authorization process. This endpoint renders an HTML login page for the user.

- **Query Parameters:**
  - `client_id` (required): The ID of the registered client.
  - `redirect_uri` (required): The callback URL where the user will be sent after login.
  - `scope` (required): A space-separated list of requested data scopes (e.g., `profile:nickname profile:uuid`).
  - `code_challenge` (required): A PKCE code challenge.
  - `code_challenge_method` (required): The method used to derive the code challenge (S256 or plain).
  - `state` (optional): An opaque value used to maintain state between the request and callback.

### `POST /xauth/login`

Handles the form submission from the authorize page.

- **Form Parameters:**
  - `client_id`, `redirect_uri`, `scope`, `state` (from the authorize step).
  - `code_challenge` (required): The code challenge from the authorize step.
  - `code_challenge_method` (required): The code challenge method (S256 or plain).
  - `username` (required): The player's username.
  - `password` (required): The player's XAuth password.
- **On Success:** Redirects the user to the `/xauth/consent` page to confirm scope access.

### `GET /xauth/consent`

Displays a consent page to the user, asking them to approve or deny the requested scopes.

- **Query Parameters:**
  - `client_id` (required): The ID of the registered client.
  - `redirect_uri` (required): The callback URL where the user will be sent after authorization.
  - `scope` (required): A space-separated list of requested data scopes.
  - `state` (optional): An opaque value used to maintain state between the request and callback.
  - `code_challenge` (required): The code challenge from the authorize step.
  - `code_challenge_method` (required): The code challenge method (S256 or plain).
  - `username` (required): The username of the authenticated player.
- **On Approval (POST):**
  - **Form Parameters:** Same as query parameters, plus `consent_action` (value: `approve`).
  - **On Success:** Redirects the user to the `redirect_uri` with a temporary `code` and the original `state`.
- **On Denial (POST):**
  - **Form Parameters:** Same as query parameters, plus `consent_action` (value: `deny`).
  - **On Success:** Redirects the user to the `redirect_uri` with an `access_denied` error.

### `POST /xauth/token`

Exchanges an authorization code for an access token. This should be a server-to-server request.

- **Form Parameters:**
  - `client_id` (required): The client ID.
  - `client_secret` (required): The client secret.
  - `code` (required): The authorization code received from the login step.
  - `code_verifier` (required): The PKCE code verifier.
- **On Success:** Returns a JSON object with the access token.
  ```json
  {
    "access_token": "your_long_lived_access_token",
    "token_type": "Bearer",
    "expires_in": 3600
  }
  ```

### `POST /xauth/token/refresh`

Exchanges a refresh token for a new access token (and optionally a new refresh token).

- **Form Parameters:**
  - `client_id` (required): The client ID.
  - `client_secret` (required): The client secret.
  - `refresh_token` (required): The refresh token obtained previously.
- **On Success:** Returns a JSON object with the new access token and refresh token.
  ```json
  {
    "access_token": "new_long_lived_access_token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "new_refresh_token"
  }
  ```

### `POST /xauth/introspect`

Allows a client to query the active state of an access or refresh token.

- **Form Parameters:**
  - `token` (required): The access token or refresh token to introspect.
  - `token_type_hint` (optional): Hint about the type of the token (`access_token` or `refresh_token`).
  - `client_id` (required): The client ID.
  - `client_secret` (required): The client secret.
- **On Success:** Returns a JSON object indicating the token's active status and associated metadata.
  ```json
  {
    "active": true,
    "scope": "profile:nickname profile:uuid",
    "client_id": "forum_client_123",
    "username": "Steve",
    "exp": 1678886400
  }
  ```
  If the token is inactive or invalid:
  ```json
  {
    "active": false
  }
  ```

### `POST /xauth/revoke`

Allows a client to revoke an access token or refresh token.

- **Form Parameters:**
  - `token` (required): The access token or refresh token to revoke.
  - `token_type_hint` (optional): Hint about the type of the token (`access_token` or `refresh_token`).
  - `client_id` (required): The client ID.
  - `client_secret` (required): The client secret.
- **On Success:** Returns an empty 200 OK response.

### `GET /xauth/user`

Fetches user data using a valid access token.

- **Headers:**
  - `Authorization: Bearer <access_token>`
- **On Success:** Returns a JSON object containing the user data for the scopes granted to the token.
  ```json
  {
    "profile:nickname": "Steve",
    "profile:uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  }
  ```

## API for Developers

XAuthConnect allows other plugins to provide custom data scopes.

### How to Add Custom Scopes

1. **Create a ScopeProvider:**
   Your class must implement the `ChernegaSergiy\XAuthConnect\api\ScopeProvider` interface.

   ```php
   // In your plugin: src/MyPlugin/EconomyScopeProvider.php
   namespace MyPlugin;

   use ChernegaSergiy\XAuthConnect\api\ScopeProvider;

   class EconomyScopeProvider implements ScopeProvider {

       public function getProvidedScopes(): array {
           return ["economy:balance", "economy:level"];
       }

       public function retrieveScopeData(string $username, array $scopes): array {
           $data = [];
           // Your logic to get player data, e.g., from EconomyAPI
           $balance = 123.45; // placeholder
           $level = 5; // placeholder

           foreach ($scopes as $scope) {
               if ($scope === 'economy:balance') {
                   $data['economy:balance'] = $balance;
               }
               if ($scope === 'economy:level') {
                   $data['economy:level'] = $level;
               }
           }
           return $data;
       }
   }
   ```

2. **Register your provider:**
   In your plugin's `onEnable()`, get the `XAuthConnect` instance and register your provider.

   ```php
   // In your plugin: src/MyPlugin/Main.php
   $xauthConnect = $this->getServer()->getPluginManager()->getPlugin("XAuthConnect");
   if ($xauthConnect instanceof \ChernegaSergiy\XAuthConnect\Main) {
       $xauthConnect->registerScopeProvider(new EconomyScopeProvider());
       $this->getLogger()->info("Registered custom economy scopes with XAuthConnect.");
   }
   ```

3. **Update Client Configuration:**
   Server administrators can now add your new scopes (`economy:balance`, `economy:level`) to the `allowed-scopes` list for any client in `config.yml`.

## Customizing the Login Page

The HTML for the authorization login page (`login.html`) is copied from the plugin's internal resources to `plugin_data/XAuthConnect/web/login.html` on first run. You can customize the login page by editing this file in the `plugin_data` folder.

**Customizing Static Assets (CSS, JS, Images):**
The plugin's web server *does* serve static files from the `plugin_data/XAuthConnect/web/static/` directory.

To include custom CSS, JavaScript, or images:
1. **Manually create** a `static/` subfolder inside `plugin_data/XAuthConnect/web/`.
2. Place your custom files (e.g., `styles.css`) inside this `static/` folder.
3. Link to them in your `login.html` using the `/xauth/assets/` URL path.

For example, if you have `plugin_data/XAuthConnect/web/static/styles.css`, you can link to it in `login.html` like this:

```html
<link rel="stylesheet" href="/xauth/assets/styles.css">
```

The template uses several placeholders that are replaced by the plugin:

- `{{client_name}}`: Displays the `name` of the application the user is logging into.
- `{{error_message}}`: Shows an error message if a previous login attempt failed. This is an HTML block, often a Bootstrap alert.
- `{{oauth_params}}`: This is a crucial placeholder that injects hidden input fields (`client_id`, `redirect_uri`, `scope`, `state`) into the form, ensuring the OAuth 2.0 parameters are passed along correctly. This must be included inside your `<form>` tag.

## Contributing

Contributions are welcome and appreciated! Here's how you can contribute:

1. Fork the project on GitHub.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

Please make sure to update tests as appropriate and adhere to the existing coding style.

## License

This project is licensed under the CSSM Unlimited License v2 (CSSM-ULv2). Please note that this is a custom license. See the [LICENSE](LICENSE) file for details.
