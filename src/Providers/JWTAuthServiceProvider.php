<?php

namespace Fluent\JWTAuth\Providers;

use CodeIgniter\Config\Factories;
use CodeIgniter\Config\Services;
use Fluent\Auth\AbstractServiceProvider;
use Fluent\Auth\Facades\Auth;
use Fluent\JWTAuth\Blacklist;
use Fluent\JWTAuth\Claims\Factory as ClaimsFactory;
use Fluent\JWTAuth\Factory;
use Fluent\JWTAuth\Http\Parser\AuthHeaders;
use Fluent\JWTAuth\Http\Parser\Cookies;
use Fluent\JWTAuth\Http\Parser\InputSource;
use Fluent\JWTAuth\Http\Parser\Parser as HttpParser;
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
                (new JWT(
                    (new Manager(
                        new Lcobucci(
                            new Builder(),
                            new Parser(),
                            static::config('secret'),
                            static::config('algo'),
                            static::config('keys')
                        ),
                        (new Blacklist(new Illuminate(Services::cache())))
                            ->setGracePeriod(static::config('blacklist_grace_period'))
                            ->setRefreshTTL(static::config('refresh_ttl')),
                        new Factory(
                            (new ClaimsFactory(Services::request()))
                                ->setTTL(static::config('ttl'))
                                ->setLeeway(static::config('leeway')),
                            (new PayloadValidator())
                                ->setRefreshTTL(static::config('refresh_ttl'))
                                ->setRequiredClaims(static::config('required_claims'))
                        )
                    ))
                    ->setBlacklistEnabled(static::config('blacklist_enabled'))
                    ->setPersistentClaims(static::config('persistent_claims')),
                    new HttpParser(
                        Services::request(),
                        [
                            new AuthHeaders(),
                            new QueryString(),
                            new InputSource(),
                            new Cookies(static::config('decrypt_cookies')),
                        ]
                    )
                ))
                ->lockSubject(static::config('lock_subject')),
                Auth::createUserProvider($config['provider']),
                Services::request()
            );
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param string $key
     * @return mixed
     */
    protected static function config($key)
    {
        return Factories::config('JWT', ['getShared' => true])->$key;
    }
}
