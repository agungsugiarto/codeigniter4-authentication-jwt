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

use CodeIgniter\Http\Request;

class HttpParser
{
    /**
     * The chain.
     *
     * @var array
     */
    private $chain;

    /**
     * The request.
     *
     * @var Request
     */
    protected $request;

    /**
     * @param  array  $chain
     * @return void
     */
    public function __construct(Request $request, array $chain = [])
    {
        $this->request = $request;
        $this->chain   = $chain;
    }

    /**
     * Get the parser chain.
     *
     * @return array
     */
    public function getChain()
    {
        return $this->chain;
    }

    /**
     * Add a new parser to the chain.
     *
     * @param array|\Fluent\JWTAuth\Contracts\Http\ParserInterface $parsers
     *
     * @return $this
     */
    public function addParser($parsers)
    {
        $this->chain = array_merge($this->chain, is_array($parsers) ? $parsers : [$parsers]);

        return $this;
    }

    /**
     * Set the order of the parser chain.
     *
     * @param  array  $chain
     * @return $this
     */
    public function setChain(array $chain)
    {
        $this->chain = $chain;

        return $this;
    }

    /**
     * Alias for setting the order of the chain.
     *
     * @param  array  $chain
     * @return $this
     */
    public function setChainOrder(array $chain)
    {
        return $this->setChain($chain);
    }

    /**
     * Iterate through the parsers and attempt to retrieve
     * a value, otherwise return null.
     *
     * @return string|null
     */
    public function parseToken()
    {
        foreach ($this->chain as $parser) {
            if ($response = $parser->parse($this->request)) {
                return $response;
            }
        }
    }

    /**
     * Check whether a token exists in the chain.
     *
     * @return bool
     */
    public function hasToken()
    {
        return $this->parseToken() !== null;
    }

    /**
     * Set the request instance.
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }
}
