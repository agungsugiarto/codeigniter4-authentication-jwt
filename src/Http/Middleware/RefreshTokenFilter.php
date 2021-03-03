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

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Fluent\Auth\Exceptions\AuthenticationException;
use Fluent\JWTAuth\Exceptions\JWTException;

class RefreshTokenFilter extends AbstractBaseFilter implements FilterInterface
{
    /**
     * {@inheritdoc}
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        $this->checkForToken($request);

        try {
            $token = $this->auth->parseToken()->refresh();
        } catch (JWTException $e) {
            throw new AuthenticationException($e->getMessage(), [], $e->getCode());
        }

        return $this->setAuthenticationHeader(service('response'), $token);
    }

    /**
     * {@inheritdoc}
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
    }
}
