<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 * (c) Agung Sugiarto <me.agungsugiarto@gmail.co>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fluent\JWTAuth\Http\Parser;

use CodeIgniter\Http\Request;
use Fluent\JWTAuth\Contracts\Http\ParserInterface;

class InputSource implements ParserInterface
{
    use KeyTrait;

    /**
     * Try to parse the token from the request input source.
     *
     * @return null|string
     */
    public function parse(Request $request)
    {
        return $request->fetchGlobal('POST', $this->key);
    }
}
