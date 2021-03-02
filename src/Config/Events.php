<?php

use CodeIgniter\Events\Events;
use Fluent\JWTAuth\Providers\JWTAuthServiceProvider;

/**
 * --------------------------------------------------------------------
 * Register Auth Service Provider.
 * --------------------------------------------------------------------
 * Register auth service provider to lifecycle application.
 */

Events::on('pre_system', [JWTAuthServiceProvider::class, 'register']);
