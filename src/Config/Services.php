<?php

namespace Fluent\JWTAuth\Config;

use CodeIgniter\Config\Factories;
use CodeIgniter\Config\BaseService;
use Fluent\JWTAuth\Blacklist;
use Fluent\JWTAuth\Claims\Factory as ClaimsFactory;
use Fluent\JWTAuth\Contracts\Providers\JWTInterface;
use Fluent\JWTAuth\Factory;
use Fluent\JWTAuth\Http\Parser\AuthHeaders;
use Fluent\JWTAuth\Http\Parser\Cookies;
use Fluent\JWTAuth\Http\Parser\HttpParser;
use Fluent\JWTAuth\Http\Parser\InputSource;
use Fluent\JWTAuth\Http\Parser\QueryString;
use Fluent\JWTAuth\JWT;
use Fluent\JWTAuth\Manager;
use Fluent\JWTAuth\Providers\JWT\Lcobucci;
use Fluent\JWTAuth\Providers\Storage\CacheStorage;
use Fluent\JWTAuth\Validators\PayloadValidator;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;

class Services extends BaseService
{
    /**
     * Service JWT.
     *
     * @return JWT
     */
    public static function jwt(bool $getShared = true)
    {
        if ($getShared) {
            return static::getSharedInstance('jwt');
        }

        return (new JWT(
            static::getSharedInstance('manager'),
            static::getSharedInstance('httpparser')
        ))
        ->lockSubject(static::config('lock_subject'));
    }

    /**
     * Service manager.
     *
     * @return Manager
     */
    public static function manager(bool $getShared = true)
    {
        if ($getShared) {
            return static::getSharedInstance('manager');
        }

        return (new Manager(
            static::getSharedInstance('lcobuccy'),
            static::getSharedInstance('blacklist'),
            static::getSharedInstance('factory')
        ))
        ->setBlacklistEnabled(static::config('blacklist_enabled'))
        ->setPersistentClaims(static::config('persistent_claims'));
    }

    /**
     * Service lcobuccy.
     *
     * @return JWTInterface
     */
    public static function lcobuccy(bool $getShared = true)
    {
        if ($getShared) {
            return static::getSharedInstance('lcobuccy');
        }

        return new Lcobucci(
            new Builder(),
            new Parser(),
            static::config('secret'),
            static::config('algo'),
            static::config('keys')
        );
    }

    /**
     * Service blacklist.
     *
     * @return Blacklist
     */
    public static function blacklist(bool $getShared = true)
    {
        if ($getShared) {
            return static::getSharedInstance('blacklist');
        }

        return (new Blacklist(new CacheStorage(static::cache())))
            ->setGracePeriod(static::config('blacklist_grace_period'))
            ->setRefreshTTL(static::config('refresh_ttl'));
    }

    /**
     * Service factory.
     *
     * @return Factory
     */
    public static function factory(bool $getShared = true)
    {
        if ($getShared) {
            return static::getSharedInstance('factory');
        }

        return new Factory(
            (new ClaimsFactory(static::getSharedInstance('request')))
                ->setTTL(static::config('ttl'))
                ->setLeeway(static::config('leeway')),
            (new PayloadValidator())
                ->setRefreshTTL(static::config('refresh_ttl'))
                ->setRequiredClaims(static::config('required_claims'))
        );
    }

    /**
     * Services httpparser.
     *
     * @return HttpParser
     */
    public static function httpparser(bool $getShared = true)
    {
        if ($getShared) {
            return static::getSharedInstance('httpparser');
        }

        return new HttpParser(
            static::getSharedInstance('request'),
            [
                new AuthHeaders(),
                new Cookies(),
                new InputSource(),
                new QueryString(),
            ]
        );
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
