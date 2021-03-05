<?php

namespace Fluent\JWTAuth\Providers;

use Fluent\Auth\AbstractServiceProvider;
use Fluent\Auth\Facades\Auth;
use Fluent\JWTAuth\Config\Services;
use Fluent\JWTAuth\JWTGuard;

class JWTAuthServiceProvider extends AbstractServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public static function register()
    {
        Auth::extend('jwt', function ($auth, $name, array $config) {
            return new JWTGuard(
                Services::jwt(),
                Services::request(),
                $auth->createUserProvider($config['provider']),
            );
        });
    }
}
