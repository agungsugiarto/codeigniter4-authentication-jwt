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

namespace Fluent\JWTAuth\Contracts\Http;

use CodeIgniter\Http\Request;

interface Parser
{
    /**
     * Parse the request.
     *
     * @return null|string
     */
    public function parse(Request $request);
}
