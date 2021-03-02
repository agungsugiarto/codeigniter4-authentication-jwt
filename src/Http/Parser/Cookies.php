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

namespace Fluent\JWTAuth\Http\Parser;

use CodeIgniter\Config\Services;
use CodeIgniter\Http\Request;
use Fluent\JWTAuth\Contracts\Http\Parser as ParserContract;

class Cookies implements ParserContract
{
    use KeyTrait;

    /**
     * Decrypt or not the cookie while parsing.
     *
     * @var bool
     */
    private $decrypt;

    public function __construct($decrypt = false)
    {
        $this->decrypt = $decrypt;
    }

    /**
     * Try to parse the token from the request cookies.
     *
     * @return null|string
     */
    public function parse(Request $request)
    {
        if ($this->decrypt && $request->fetchGlobal('cookie', $this->key)) {
            return Services::encrypter()->decrypt($request->fetchGlobal('cookie', $this->key));
        }

        return $request->fetchGlobal('cookie', $this->key);
    }
}
