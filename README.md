# CodeIgniter4 Authentication JWT

[![tests](https://github.com/agungsugiarto/codeigniter4-authentication-jwt/actions/workflows/php.yml/badge.svg)](https://github.com/agungsugiarto/codeigniter4-authentication-jwt/actions/workflows/php.yml)
[![Latest Stable Version](https://poser.pugx.org/agungsugiarto/codeigniter4-authentication-jwt/v)](https://github.com/agungsugiarto/codeigniter4-authentication-jwt/releases)
[![Total Downloads](https://poser.pugx.org/agungsugiarto/codeigniter4-authentication-jwt/downloads)](https://packagist.org/packages/agungsugiarto/codeigniter4-authentication-jwt/stats)
[![Latest Unstable Version](https://poser.pugx.org/agungsugiarto/codeigniter4-authentication-jwt/v/unstable)](https://packagist.org/packages/agungsugiarto/codeigniter4-authentication-jwt)
[![License](https://poser.pugx.org/agungsugiarto/codeigniter4-authentication-jwt/license)](https://github.com/agungsugiarto/codeigniter4-authentication-jwt/blob/master/LICENSE.md)
## About
JSON Web Token for codeigniter4-authentication. This package is port from [tymondesigns/jwt-auth](https://github.com/tymondesigns/jwt-auth) for compability with [agungsugiarto/codeigniter4-authentication](https://github.com/agungsugiarto/codeigniter4-authentication).

## Documentation
### Install Via Composer
```sh
composer require agungsugiarto/codeigniter4-authentication-jwt
```

### Copy the config
Copy the config file from `vendor/agungsugiarto/codeigniter4-authentication-jwt/src/Config/JWT.php` to config folder of your codeigniter4 application and change class extends from `BaseConfig` to `\Fluent\JWTAuth\Config\JWT`

### Update your User entities
Firstly you need to implement the `Fluent\JWTAuth\Contracts\JWTSubjectInterface` contract on your User entities, which requires that you implement the 2 methods `getJWTIdentifier()` and `getJWTCustomClaims()`.

The example below should give you an idea of how this could look. Obviously you should make any changes, as necessary, to suit your own needs.
```php
namespace App\Entities;

//..
use Fluent\JWTAuth\Contracts\JWTSubjectInterface;

class User extends Entity implements
    //..
    JWTSubjectInterface
{
    /**
     * {@inheritdoc}
     */
    public function getJWTIdentifier()
    {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
```

### Configure Auth guard

Inside the `app/Config/Auth.php` file you will need to make a few changes to configure codeigniter4-authentication to use the jwt guard to power your application authentication.

Make the following changes to the file:
```php
public $guards = [
    //..
    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
];
```
Here we are telling the api guard to use the jwt driver, and we are setting the api guard.

We can now use codeigniter4-authentication built in Auth system, with codeigniter4-authentication-jwt doing the work behind the scenes!

### Add some basic authentication routes
First let's add some routes in app/Config/Routes.php as follows:
```php
$routes->group('jwt', function ($routes) {
    $routes->post('login', 'JwtauthController::login');
    $routes->post('logout', 'JwtauthController::logout', ['filter' => 'auth:api']);
    $routes->post('refresh', 'JwtauthController::refresh', ['filter' => 'auth:api']);
    $routes->match(['get', 'post'], 'user', 'JwtauthController::user', ['filter' => 'auth:api']);
});
```

### Create the AuthController
Then create the `JwtauthController`, either manually or by running the spark command:
```sh
php spark make:controller JwtauthController
```
Then add the following:
```php
<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\API\ResponseTrait;

class JwtauthController extends BaseController
{
    use ResponseTrait;

    /**
     * Get a JWT via given credentials.
     *
     * @return \CodeIgniter\Http\Response
     */
    public function login()
    {
        // Validate this credentials request.
        if (! $this->validate(['email' => 'required|valid_email', 'password' => 'required'])) {
            return $this->fail($this->validator->getErrors());
        }

        $credentials = [
            'email' => $this->request->getPost('email'),
            'password' => $this->request->getPost('password')
        ];

        if (! $token = auth('api')->attempt($credentials)) {
            return $this->fail(lang('Auth.failed'), 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \CodeIgniter\Http\Response
     */
    public function user()
    {
        return $this->response->setJson(auth('api')->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \CodeIgniter\Http\Response
     */
    public function logout()
    {
        auth('api')->logout();

        return $this->response->setJson(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \CodeIgniter\Http\Response
     */
    public function refresh()
    {
        return $this->respondWithToken(auth('api')->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \CodeIgniter\Http\Response
     */
    protected function respondWithToken($token)
    {
        return $this->response->setJson([
            'access_token' => $token,
            'token_type'   => 'bearer',
            'expires_in'   => auth('api')->factory()->getTTL() * 60,
        ]);
    }
}
```
You should now be able to POST to the login endpoint (e.g. http://example.dev/jwt/login) with some valid credentials and see a response like:
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
    "token_type": "bearer",
    "expires_in": 3600
}
```
This token can then be used to make authenticated requests to your application.

### Authenticated requests
There are a number of ways to send the token via http:

**Authorization header**

```Authorization: Bearer eyJhbGciOiJIUzI1NiI...```

**Query string parameter**

```http://example.dev/me?token=eyJhbGciOiJIUzI1NiI...```

**Post parameter**

**Cookies**

## Methods
The following methods are available on the Auth guard instance.

### Multiple Guards
If the newly created 'api' guard is not set as a default guard or you have defined multiple guards to handle authentication, you should specify the guard when calling auth().

```php
 $token = auth('api')->attempt($credentials);
```

### attempt()
Attempt to authenticate a user via some credentials.

```php
// Generate a token for the user if the credentials are valid
$token = auth('api')->attempt($credentials);
```
This will return either a jwt or boolean

### login()
Log a user in and return a jwt for them.

```php
// Get some user from somewhere
$user = (new UserModel())->first();

// Get the token
$token = auth('api')->login($user);
```

### user()
Get the currently authenticated user.

```php
// Get the currently authenticated user
$user = auth('api')->user();
```
If the user is not then authenticated, then null will be returned.

### userOrFail()
Get the currently authenticated user or throw an exception.

```php
try {
    $user = auth('api')->userOrFail();
} catch (\Fluent\JWTAuth\Exceptions\UserNotDefinedException $e) {
    // do something
}
```
If the user is not set, then a `Fluent\JWTAuth\Exceptions\UserNotDefinedException` will be thrown

### logout()
Log the user out - which will invalidate the current token and unset the authenticated user.

```php
auth('api')->logout();

// Pass true to force the token to be blacklisted "forever"
auth('api')->logout(true);
```

### refresh()
Refresh a token, which invalidates the current one

```php
$newToken = auth('api')->refresh();

// Pass true as the first param to force the token to be blacklisted "forever".
// The second parameter will reset the claims for the new token
$newToken = auth('api')->refresh(true, true);
```

### invalidate()
Invalidate the token (add it to the blacklist)

```php
auth('api')->invalidate();

// Pass true as the first param to force the token to be blacklisted "forever".
auth('api')->invalidate(true);
```

### tokenById()
Get a token based on a given user's id.

```php
$token = auth('api')->tokenById(123);

```

### payload()
Get the raw JWT payload

```php
$payload = auth('api')->payload();

// then you can access the claims directly e.g.
$payload->get('sub'); // = 123
$payload['jti']; // = 'asfe4fq434asdf'
$payload('exp') // = 123456
$payload->toArray(); // = ['sub' => 123, 'exp' => 123456, 'jti' => 'asfe4fq434asdf'] etc
```

### validate()
Validate a user's credentials


```php
if (auth('api')->validate($credentials)) {
    // credentials are valid
}
```

## More advanced usage
### Adding custom claims
```php
$token = auth('api')->claims(['foo' => 'bar'])->attempt($credentials);
```

### Set the token explicitly
```php
$user = auth('api')->setToken('eyJhb...')->user();
```

### Set the request instance explicitly
```php
$user = auth('api')->setRequest($request)->user();
```

### Override the token ttl
```php
$token = auth('api')->setTTL(7200)->attempt($credentials);
```

## Contributing
Contributions are very welcome.

## License

Released under the MIT License, see [LICENSE](LICENSE.md).
