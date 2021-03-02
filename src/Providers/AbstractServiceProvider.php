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

use Fluent\JWTAuth\Blacklist;
use Fluent\JWTAuth\Claims\Factory as ClaimFactory;
use Fluent\JWTAuth\Console\JWTGenerateSecretCommand;
use Fluent\JWTAuth\Contracts\Providers\Auth;
use Fluent\JWTAuth\Contracts\Providers\JWT as JWTContract;
use Fluent\JWTAuth\Contracts\Providers\Storage;
use Fluent\JWTAuth\Factory;
use Fluent\JWTAuth\Http\Middleware\Authenticate;
use Fluent\JWTAuth\Http\Middleware\AuthenticateAndRenew;
use Fluent\JWTAuth\Http\Middleware\Check;
use Fluent\JWTAuth\Http\Middleware\RefreshToken;
use Fluent\JWTAuth\Http\Parser\AuthHeaders;
use Fluent\JWTAuth\Http\Parser\Cookies;
use Fluent\JWTAuth\Http\Parser\InputSource;
use Fluent\JWTAuth\Http\Parser\Parser;
use Fluent\JWTAuth\Http\Parser\QueryString;
use Fluent\JWTAuth\Http\Parser\RouteParams;
use Fluent\JWTAuth\JWT;
use Fluent\JWTAuth\JWTAuth;
use Fluent\JWTAuth\JWTGuard;
use Fluent\JWTAuth\Manager;
use Fluent\JWTAuth\Providers\JWT\Lcobucci;
use Fluent\JWTAuth\Providers\JWT\Namshi;
use Fluent\JWTAuth\Validators\PayloadValidator;
use Illuminate\Support\ServiceProvider;
use Lcobucci\JWT\Builder as JWTBuilder;
use Lcobucci\JWT\Parser as JWTParser;
use Namshi\JOSE\JWS;

use function is_string;

abstract class AbstractServiceProvider extends ServiceProvider
{
    /**
     * The middleware aliases.
     *
     * @var array
     */
    protected $middlewareAliases = [
        'jwt.auth'    => Authenticate::class,
        'jwt.check'   => Check::class,
        'jwt.refresh' => RefreshToken::class,
        'jwt.renew'   => AuthenticateAndRenew::class,
    ];

    /**
     * Boot the service provider.
     *
     * @return void
     */
    abstract public function boot();

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerAliases();

        $this->registerJWTProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerManager();
        $this->registerTokenParser();

        $this->registerJWT();
        $this->registerJWTAuth();
        $this->registerPayloadValidator();
        $this->registerClaimFactory();
        $this->registerPayloadFactory();
        $this->registerJWTCommand();

        $this->commands('Fluent.jwt.secret');
    }

    /**
     * Extend Laravel's Auth.
     *
     * @return void
     */
    protected function extendAuthGuard()
    {
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            $guard = new JWTGuard(
                $app['Fluent.jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    /**
     * Bind some aliases.
     *
     * @return void
     */
    protected function registerAliases()
    {
        $this->app->alias('Fluent.jwt', JWT::class);
        $this->app->alias('Fluent.jwt.auth', JWTAuth::class);
        $this->app->alias('Fluent.jwt.provider.jwt', JWTContract::class);
        $this->app->alias('Fluent.jwt.provider.jwt.namshi', Namshi::class);
        $this->app->alias('Fluent.jwt.provider.jwt.lcobucci', Lcobucci::class);
        $this->app->alias('Fluent.jwt.provider.auth', Auth::class);
        $this->app->alias('Fluent.jwt.provider.storage', Storage::class);
        $this->app->alias('Fluent.jwt.manager', Manager::class);
        $this->app->alias('Fluent.jwt.blacklist', Blacklist::class);
        $this->app->alias('Fluent.jwt.payload.factory', Factory::class);
        $this->app->alias('Fluent.jwt.validators.payload', PayloadValidator::class);
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     *
     * @return void
     */
    protected function registerJWTProvider()
    {
        $this->registerNamshiProvider();
        $this->registerLcobucciProvider();

        $this->app->singleton('Fluent.jwt.provider.jwt', function ($app) {
            return $this->getConfigInstance('providers.jwt');
        });
    }

    /**
     * Register the bindings for the Lcobucci JWT provider.
     *
     * @return void
     */
    protected function registerNamshiProvider()
    {
        $this->app->singleton('Fluent.jwt.provider.jwt.namshi', function ($app) {
            return new Namshi(
                new JWS(['typ' => 'JWT', 'alg' => $this->config('algo')]),
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Lcobucci JWT provider.
     *
     * @return void
     */
    protected function registerLcobucciProvider()
    {
        $this->app->singleton('Fluent.jwt.provider.jwt.lcobucci', function ($app) {
            return new Lcobucci(
                new JWTBuilder(),
                new JWTParser(),
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Auth provider.
     *
     * @return void
     */
    protected function registerAuthProvider()
    {
        $this->app->singleton('Fluent.jwt.provider.auth', function () {
            return $this->getConfigInstance('providers.auth');
        });
    }

    /**
     * Register the bindings for the Storage provider.
     *
     * @return void
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('Fluent.jwt.provider.storage', function () {
            return $this->getConfigInstance('providers.storage');
        });
    }

    /**
     * Register the bindings for the JWT Manager.
     *
     * @return void
     */
    protected function registerManager()
    {
        $this->app->singleton('Fluent.jwt.manager', function ($app) {
            $instance = new Manager(
                $app['Fluent.jwt.provider.jwt'],
                $app['Fluent.jwt.blacklist'],
                $app['Fluent.jwt.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $this->config('blacklist_enabled'))
                            ->setPersistentClaims($this->config('persistent_claims'));
        });
    }

    /**
     * Register the bindings for the Token Parser.
     *
     * @return void
     */
    protected function registerTokenParser()
    {
        $this->app->singleton('Fluent.jwt.parser', function ($app) {
            $parser = new Parser(
                $app['request'],
                [
                    new AuthHeaders(),
                    new QueryString(),
                    new InputSource(),
                    new RouteParams(),
                    new Cookies($this->config('decrypt_cookies')),
                ]
            );

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

    /**
     * Register the bindings for the main JWT class.
     *
     * @return void
     */
    protected function registerJWT()
    {
        $this->app->singleton('Fluent.jwt', function ($app) {
            return (new JWT(
                $app['Fluent.jwt.manager'],
                $app['Fluent.jwt.parser']
            ))->lockSubject($this->config('lock_subject'));
        });
    }

    /**
     * Register the bindings for the main JWTAuth class.
     *
     * @return void
     */
    protected function registerJWTAuth()
    {
        $this->app->singleton('Fluent.jwt.auth', function ($app) {
            return (new JWTAuth(
                $app['Fluent.jwt.manager'],
                $app['Fluent.jwt.provider.auth'],
                $app['Fluent.jwt.parser']
            ))->lockSubject($this->config('lock_subject'));
        });
    }

    /**
     * Register the bindings for the Blacklist.
     *
     * @return void
     */
    protected function registerJWTBlacklist()
    {
        $this->app->singleton('Fluent.jwt.blacklist', function ($app) {
            $instance = new Blacklist($app['Fluent.jwt.provider.storage']);

            return $instance->setGracePeriod($this->config('blacklist_grace_period'))
                            ->setRefreshTTL($this->config('refresh_ttl'));
        });
    }

    /**
     * Register the bindings for the payload validator.
     *
     * @return void
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('Fluent.jwt.validators.payload', function () {
            return (new PayloadValidator())
                ->setRefreshTTL($this->config('refresh_ttl'))
                ->setRequiredClaims($this->config('required_claims'));
        });
    }

    /**
     * Register the bindings for the Claim Factory.
     *
     * @return void
     */
    protected function registerClaimFactory()
    {
        $this->app->singleton('Fluent.jwt.claim.factory', function ($app) {
            $factory = new ClaimFactory($app['request']);
            $app->refresh('request', $factory, 'setRequest');

            return $factory->setTTL($this->config('ttl'))
                           ->setLeeway($this->config('leeway'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     *
     * @return void
     */
    protected function registerPayloadFactory()
    {
        $this->app->singleton('Fluent.jwt.payload.factory', function ($app) {
            return new Factory(
                $app['Fluent.jwt.claim.factory'],
                $app['Fluent.jwt.validators.payload']
            );
        });
    }

    /**
     * Register the Artisan command.
     *
     * @return void
     */
    protected function registerJWTCommand()
    {
        $this->app->singleton('Fluent.jwt.secret', function () {
            return new JWTGenerateSecretCommand();
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param  string  $key
     * @param  string  $default
     * @return mixed
     */
    protected function config($key, $default = null)
    {
        return config("jwt.$key", $default);
    }

    /**
     * Get an instantiable configuration instance.
     *
     * @param  string  $key
     * @return mixed
     */
    protected function getConfigInstance($key)
    {
        $instance = $this->config($key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
