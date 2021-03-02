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

namespace Fluent\JWTAuth\Exceptions;

use Exception;
use Fluent\JWTAuth\Claims\Claim;

class InvalidClaimException extends JWTException
{
    /**
     * @param  int  $code
     * @return void
     */
    public function __construct(Claim $claim, $code = 0, ?Exception $previous = null)
    {
        parent::__construct('Invalid value provided for claim [' . $claim->getName() . ']', $code, $previous);
    }
}
