<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fluent\JWTAuth\Test\Claims;

use Fluent\JWTAuth\Claims\NotBefore;
use Fluent\JWTAuth\Exceptions\InvalidClaimException;
use Fluent\JWTAuth\Test\AbstractTestCase;

class NotBeforeTest extends AbstractTestCase
{
    /** @test */
    public function it_should_throw_an_exception_when_passing_an_invalid_value()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [nbf]');

        new NotBefore('foo');
    }
}
