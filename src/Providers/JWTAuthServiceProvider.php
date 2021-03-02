<?php

namespace Fluent\JWTAuth\Providers;

use CodeIgniter\Config\Services;
use Fluent\Auth\AbstractServiceProvider;
use Fluent\Auth\Facades\Auth;
use Fluent\JWTAuth\Blacklist;
use Fluent\JWTAuth\Claims\Factory as ClaimsFactory;
use Fluent\JWTAuth\Factory;
use Fluent\JWTAuth\Http\Parser\AuthHeaders;
use Fluent\JWTAuth\Http\Parser\Cookies;
use Fluent\JWTAuth\Http\Parser\InputSource;
use Fluent\JWTAuth\Http\Parser\Parser as ParserParser;
use Fluent\JWTAuth\Http\Parser\QueryString;
use Fluent\JWTAuth\JWT;
use Fluent\JWTAuth\JWTGuard;
use Fluent\JWTAuth\Manager;
use Fluent\JWTAuth\Providers\JWT\Lcobucci;
use Fluent\JWTAuth\Providers\Storage\Illuminate;
use Fluent\JWTAuth\Validators\PayloadValidator;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;

class JWTAuthServiceProvider extends AbstractServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public static function register()
    {
        Auth::extend('jwt', function ($auth, $name, array $config) {
            return new JWTGuard(
                new JWT(
                    new Manager(
                        new Lcobucci(
                            new Builder(),
                            new Parser(),
                            'HUDq86iixx97nJZopsu3V5vHdzswPw29qC8PwylruFKJI5paAY5ogqiTBCnIUYKm',
                            'HS256',
                            []
                        ),
                        new Blacklist(new Illuminate(Services::cache())),
                        new Factory(
                            new ClaimsFactory(Services::request()),
                            (new PayloadValidator())
                                ->setRefreshTTL(20160)
                                ->setRequiredClaims([
                                    'iss',
                                    'iat',
                                    'exp',
                                    'nbf',
                                    'sub',
                                    'jti',
                                ])
                        )
                    ),
                    new ParserParser(
                        Services::request(),
                        [
                            new AuthHeaders(),
                            new QueryString(),
                            new InputSource(),
                            new Cookies(false),
                        ]
                    )
                ),
                Auth::createUserProvider($config['provider']),
                Services::request()
            );
        });
    }
}
