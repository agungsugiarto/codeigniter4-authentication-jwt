<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fluent\JWTAuth\Test\Stubs;

use Fluent\Auth\Contracts\AuthenticatorInterface;
use Fluent\Auth\Traits\AuthenticatableTrait;
use Fluent\JWTAuth\Contracts\JWTSubjectInterface;

class LaravelUserStub extends UserStub implements AuthenticatorInterface, JWTSubjectInterface
{
    use AuthenticatableTrait;
}
