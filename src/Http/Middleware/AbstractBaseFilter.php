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

namespace Fluent\JWTAuth\Http\Middleware;

use CodeIgniter\Http\Request;
use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;
use Fluent\Auth\Exceptions\AuthenticationException;
use Fluent\Auth\Facades\Auth;
use Fluent\JWTAuth\Exceptions\JWTException;
use Fluent\JWTAuth\JWTGuard;

abstract class AbstractBaseFilter
{
    /**
     * The JWT Authenticator.
     *
     * @var JWTGuard
     */
    protected $auth;

    /**
     * Create a new BaseMiddleware instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->auth = Auth::guard('api');
    }

    /**
     * Check the request for the presence of a token.
     *
     * @throws BadRequestHttpException
     * @return void
     */
    public function checkForToken(Request $request)
    {
        if (! $this->auth->parser()->setRequest($request)->hasToken()) {
            throw new AuthenticationException('Token not provided');
        }
    }

    /**
     * Attempt to authenticate a user via the token in the request.
     *
     * @throws UnauthorizedHttpException
     * @return void
     */
    public function authenticate(Request $request)
    {
        $this->checkForToken($request);

        try {
            if (! $this->auth->check()) {
                throw new AuthenticationException('User not found');
            }
        } catch (JWTException $e) {
            throw new AuthenticationException($e->getMessage(), [], $e->getCode());
        }
    }

    /**
     * Set the authentication header.
     *
     * @param  string|null $token
     * @return ResponseInterface
     */
    protected function setAuthenticationHeader(Response $response, $token = null)
    {
        $token = $token ?: $this->auth->refresh();

        return $response->setHeader('Authorization', 'Bearer ' . $token);
    }
}
