<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 * (c) Agung Sugiarto <me.agungsugiarto@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fluent\JWTAuth\Config;

use CodeIgniter\Config\BaseConfig;

class JWT extends BaseConfig
{
    /**
     * --------------------------------------------------------------------------
     * JWT Authentication Secret
     * --------------------------------------------------------------------------
     *
     * Don't forget to set this in your .env file, as it will be used to sign
     * your tokens. A helper command is provided for this:
     * `php artisan jwt:secret`
     *
     * Note: This will be used for Symmetric algorithms only (HMAC),
     * since RSA and ECDSA use a private/public key combo (See below).
     *
     * @var string
     */
    public $secret = '';

    /**
     * --------------------------------------------------------------------------
     * JWT Authentication Keys
     * --------------------------------------------------------------------------
     *
     * The algorithm you are using, will determine whether your tokens are
     * signed with a random string (defined in `JWT_SECRET`) or using the
     * following public & private keys.
     *
     * Symmetric Algorithms:
     * HS256, HS384 & HS512 will use `JWT_SECRET`.
     *
     * Asymmetric Algorithms:
     * RS256, RS384 & RS512 / ES256, ES384 & ES512 will use the keys below.
     *
     * @var array<string, string>
     */
    public $keys = [

        /**
         * --------------------------------------------------------------------------
         * Public Key
         * --------------------------------------------------------------------------
         *
         * A path or resource to your public key.
         *
         * E.g. 'file://path/to/public/key'
         *
         * @var array<string, string>
         */
        'public' => '',

        /**
         * --------------------------------------------------------------------------
         * Private Key
         * --------------------------------------------------------------------------
         *
         * A path or resource to your private key.
         *
         * E.g. 'file://path/to/private/key'
         *
         * @var array<string, string>
         */
        'private' => '',

        /**
         * --------------------------------------------------------------------------
         * Passphrase
         * --------------------------------------------------------------------------
         *
         * The passphrase for your private key. Can be null if none set.
         *
         * @var array<string, string>
         */
        'passphrase' => '',
    ];

    /**
     * --------------------------------------------------------------------------
     * JWT time to live
     * --------------------------------------------------------------------------
     *
     * Specify the length of time (in minutes) that the token will be valid for.
     * Defaults to 1 hour.
     *
     * You can also set this to null, to yield a never expiring token. Some people
     * may want this behaviour for e.g. a mobile app. This is not particularly
     * recommended, so make sure you have appropriate systems in place to
     * revoke the token if necessary. Notice: If you set this to null
     * you should remove 'exp' element from 'required_claims' list.
     *
     * @var int
     */
    public $ttl = 60;

    /**
     * --------------------------------------------------------------------------
     * Refresh time to live
     * --------------------------------------------------------------------------
     *
     * Specify the length of time (in minutes) that the token can be refreshed
     * within. I.E. The user can refresh their token within a 2 week window of
     * the original token being created until they must re-authenticate.
     * Defaults to 2 weeks.
     *
     * You can also set this to null, to yield an infinite refresh time.
     * Some may want this instead of never expiring tokens for e.g. a mobile app.
     * This is not particularly recommended, so make sure you have appropriate
     * systems in place to revoke the token if necessary.
     *
     * @var int
     */
    public $refresh_ttl = 20160;

    /**
     * --------------------------------------------------------------------------
     * JWT hashing algorithm
     * --------------------------------------------------------------------------
     *
     * Specify the hashing algorithm that will be used to sign the token.
     *
     * @see https://github.com/agungsugiarto/codeigniter4-authentication-jwt/blob/da2f8ad6429bb6ddc4e965cdc47953412044774d/src/Providers/JWT/Lcobucci.php#L83-L93
     * for possible values.
     *
     * @var string
     */
    public $algo = 'HS256';

    /**
     * --------------------------------------------------------------------------
     * Required Claims
     * --------------------------------------------------------------------------
     *
     * Specify the required claims that must exist in any token.
     * A TokenInvalidException will be thrown if any of these claims are not
     * present in the payload.
     *
     * @var array<string>
     */
    public $required_claims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
    ];

    /**
     * --------------------------------------------------------------------------
     * Persistent Claims
     * --------------------------------------------------------------------------
     *
     * Specify the claim keys to be persisted when refreshing a token.
     * `sub` and `iat` will automatically be persisted, in
     * addition to the these claims.
     *
     * Note: If a claim does not exist then it will be ignored.
     *
     * @var array<string>
     */
    public $persistent_claims = [
        // 'foo',
        // 'bar',
    ];

    /**
     * --------------------------------------------------------------------------
     * Lock Subject
     * --------------------------------------------------------------------------
     *
     * This will determine whether a `prv` claim is automatically added to
     * the token. The purpose of this is to ensure that if you have multiple
     * authentication models e.g. `App\User` & `App\OtherPerson`, then we
     * should prevent one authentication request from impersonating another,
     * if 2 tokens happen to have the same id across the 2 different models.
     *
     * Under specific circumstances, you may want to disable this behaviour
     * e.g. if you only have one authentication model, then you would save
     * a little on token size.
     *
     * @var bool
     */
    public $lock_subject = true;

    /**
     * --------------------------------------------------------------------------
     * Leeway
     * --------------------------------------------------------------------------
     *
     * This property gives the jwt timestamp claims some "leeway".
     * Meaning that if you have any unavoidable slight clock skew on
     * any of your servers then this will afford you some level of cushioning.
     *
     * This applies to the claims `iat`, `nbf` and `exp`.
     *
     * Specify in seconds - only if you know you need it.
     *
     * @var int
     */
    public $leeway = 0;

    /**
     * --------------------------------------------------------------------------
     * Blacklist Enabled
     * --------------------------------------------------------------------------
     *
     * In order to invalidate tokens, you must have the blacklist enabled.
     * If you do not want or need this functionality, then set this to false.
     *
     * @var bool
     */
    public $blacklist_enabled = true;

    /**
     * -------------------------------------------------------------------------
     * Blacklist Grace Period
     * -------------------------------------------------------------------------
     *
     * When multiple concurrent requests are made with the same JWT,
     * it is possible that some of them fail, due to token regeneration
     * on every request.
     *
     * Set grace period in seconds to prevent parallel request failure.
     *
     * @var int
     */
    public $blacklist_grace_period = 0;
}
