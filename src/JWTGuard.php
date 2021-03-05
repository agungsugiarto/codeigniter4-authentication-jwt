<?php

/**
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 * (c) Agung Sugiarto <me.agungsugiarto@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fluent\JWTAuth;

use BadMethodCallException;
use CodeIgniter\Events\Events;
use CodeIgniter\HTTP\RequestInterface;
use Exception;
use Fluent\Auth\Contracts\AuthenticationInterface;
use Fluent\Auth\Contracts\AuthenticatorInterface;
use Fluent\Auth\Contracts\UserProviderInterface;
use Fluent\Auth\Traits\GuardHelperTrait;
use Fluent\JWTAuth\Exceptions\JWTException;
use Fluent\JWTAuth\Exceptions\UserNotDefinedException;
use Fluent\JWTAuth\JWT;
use Fluent\JWTAuth\Payload;
use Fluent\JWTAuth\Token;

use function call_user_func_array;
use function method_exists;

class JWTGuard implements AuthenticationInterface
{
    use GuardHelperTrait;

    /** @var AuthenticatorInterface */
    protected $lastAttempted;

    /**
     * The JWT instance.
     *
     * @var JWT
     */
    protected $jwt;

    /** @var RequestInterface */
    protected $request;

    /**
     * Instantiate the class.
     *
     * @return void
     */
    public function __construct(JWT $jwt, RequestInterface $request, UserProviderInterface $provider)
    {
        $this->jwt      = $jwt;
        $this->request  = $request;
        $this->provider = $provider;
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        if (
            $this->jwt->setRequest($this->request)->getToken() &&
            ($payload = $this->jwt->check(true))
        ) {
            $this->user = $this->provider->findById($payload['sub']);

            Events::trigger('fireLoginEvent', $this->user, true);
        }

        return $this->user;
    }

    /**
     * Get the currently authenticated user or throws an exception.
     *
     * @return AuthenticatorInterface
     * @throws UserNotDefinedException
     */
    public function userOrFail()
    {
        if (! $user = $this->user()) {
            throw new UserNotDefinedException();
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function validate(array $credentials): bool
    {
        $this->lastAttempted = $user = $this->provider->findByCredentials($credentials);

        return $this->hasValidCredentials($user, $credentials);
    }

    /**
     * {@inheritdoc}
     */
    public function attempt(array $credentials, bool $remember = true)
    {
        Events::trigger('fireAttemptEvent', $credentials, $remember);

        $this->lastAttempted = $user = $this->provider->findByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            // We can return JWT token if pass second argument set to true,
            // otherwise will be return bool.
            return $this->login($user, $remember);
        }

        Events::trigger('fireFailedEvent', $user, $credentials);

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function login(AuthenticatorInterface $user, bool $remember = true)
    {
        $token = $this->jwt->fromUser($user);

        $this->setToken($token)->setUser($user);

        Events::trigger('fireLoginEvent', $user, $remember);

        // Provide codeigniter4/authentitication-implementation
        Events::trigger('login', $user, $remember);

        return $remember ? $token : true;
    }

    /**
     * {@inheritdoc}
     */
    public function logout($forceForever = false)
    {
        $this->requireToken()->invalidate($forceForever);

        Events::trigger('fireLogoutEvent', $this->user);

        // Provide codeigniter4/authentitication-implementation
        Events::trigger('logout', $this->user);

        $this->user = null;
        $this->jwt->unsetToken();
    }

    /**
     * Refresh the token.
     *
     * @param bool $forceForever
     * @param bool $resetClaims
     * @return string
     */
    public function refresh($forceForever = false, $resetClaims = false)
    {
        return $this->requireToken()->refresh($forceForever, $resetClaims);
    }

    /**
     * Invalidate the token.
     *
     * @param  bool  $forceForever
     * @return JWT
     */
    public function invalidate($forceForever = false)
    {
        return $this->requireToken()->invalidate($forceForever);
    }

    /**
     * Create a new token by User id.
     *
     * @param  mixed  $id
     * @return string|null
     */
    public function tokenById($id)
    {
        if ($user = $this->provider->findById($id)) {
            return $this->jwt->fromUser($user);
        }
    }

    /**
     * Log a user into the application using their credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log the given User into the application.
     *
     * @param  mixed  $id
     * @return bool
     */
    public function onceUsingId($id)
    {
        if ($user = $this->provider->findById($id)) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function loginById($userId, bool $remember = false)
    {
        if ($user = $this->provider->findById($userId)) {
            $this->login($user, $remember);

            return $user;
        }

        return false;
    }

    /**
     * Add any custom claims.
     *
     * @param  array  $claims
     * @return $this
     */
    public function claims(array $claims)
    {
        $this->jwt->claims($claims);

        return $this;
    }

    /**
     * Get the raw Payload instance.
     *
     * @return Payload
     */
    public function getPayload()
    {
        return $this->requireToken()->getPayload();
    }

    /**
     * Alias for getPayload().
     *
     * @return Payload
     */
    public function payload()
    {
        return $this->getPayload();
    }

    /**
     * Set the token.
     *
     * @param Token|string $token
     * @return $this
     */
    public function setToken($token)
    {
        $this->jwt->setToken($token);

        return $this;
    }

    /**
     * Set the token ttl.
     *
     * @param int $ttl
     * @return $this
     */
    public function setTTL($ttl)
    {
        $this->jwt->factory()->setTTL($ttl);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * {@inheritdoc}
     */
    public function setProvider(UserProviderInterface $provider)
    {
        $this->provider = $provider;

        return $this;
    }

    /**
     * Return the currently cached user.
     *
     * @return AuthenticatorInterface|null
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Get the current request instance.
     *
     * @return RequestInterface
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * Set the current request instance.
     *
     * @return $this
     */
    public function setRequest(RequestInterface $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Get the last user we attempted to authenticate.
     *
     * @return AuthenticatorInterface
     */
    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param mixed $user
     * @param array $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        $validated = $user !== null && $this->provider->validateCredentials($user, $credentials);

        if ($validated) {
            Events::trigger('fireValidatedEvent', $user);
        }

        return $validated;
    }

    /**
     * Ensure that a token is available in the request.
     *
     * @throws JWTException
     * @return JWT
     */
    protected function requireToken()
    {
        if (! $this->jwt->setRequest($this->getRequest())->getToken()) {
            throw new JWTException('Token could not be parsed from the request.');
        }

        return $this->jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function getSessionName()
    {
        throw new Exception('Not implemented.');
    }

    /**
     * {@inheritdoc}
     */
    public function getCookieName()
    {
        throw new Exception('Not implemented.');
    }

    /**
     * {@inheritdoc}
     */
    public function viaRemember()
    {
        throw new Exception('Not implemented.');
    }

    /**
     * Magically call the JWT instance.
     *
     * @param  string  $method
     * @param  array  $parameters
     * @throws BadMethodCallException
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        if (method_exists($this->jwt, $method)) {
            return call_user_func_array([$this->jwt, $method], $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
