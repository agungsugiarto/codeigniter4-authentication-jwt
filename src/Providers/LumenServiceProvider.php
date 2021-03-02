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

namespace Fluent\JWTAuth\Providers;

use Fluent\JWTAuth\Http\Parser\AuthHeaders;
use Fluent\JWTAuth\Http\Parser\InputSource;
use Fluent\JWTAuth\Http\Parser\LumenRouteParams;
use Fluent\JWTAuth\Http\Parser\QueryString;

use function realpath;

class LumenServiceProvider extends AbstractServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function boot()
    {
        $this->app->configure('jwt');

        $path = realpath(__DIR__ . '/../../config/config.php');
        $this->mergeConfigFrom($path, 'jwt');

        $this->app->routeMiddleware($this->middlewareAliases);

        $this->extendAuthGuard();

        $this->app['Fluent.jwt.parser']->setChain([
            new AuthHeaders(),
            new QueryString(),
            new InputSource(),
            new LumenRouteParams(),
        ]);
    }
}
