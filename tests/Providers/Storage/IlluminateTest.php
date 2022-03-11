<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fluent\JWTAuth\Test\Providers\Storage;

use CodeIgniter\Cache\CacheInterface;
use CodeIgniter\Config\Services;
use Mockery;
use Fluent\JWTAuth\Providers\Storage\CacheStorage as Storage;
use Fluent\JWTAuth\Test\AbstractTestCase;
use Fluent\JWTAuth\Test\Stubs\TaggedStorage;

class IlluminateTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\CodeIgniter\Cache\CacheInterface
     */
    protected $cache;

    /**
     * @var \Fluent\JWTAuth\Providers\Storage\CacheStorage
     */
    protected $storage;

    public function setUp(): void
    {
        parent::setUp();

        $this->cache = Mockery::mock(CacheInterface::class);
        $this->storage = new Storage($this->cache);
    }

    /** @test */
    public function it_should_add_the_item_to_storage()
    {
        $this->cache->shouldReceive('save')->with('foo', 'bar', 10)->once();

        $this->storage->add('foo', 'bar', 10);
    }

    /** @test */
    public function it_should_add_the_item_to_storage_forever()
    {
        $this->cache->shouldReceive('save')->with('foo', 'bar', 0)->once();

        $this->storage->forever('foo', 'bar');
    }

    /** @test */
    public function it_should_get_an_item_from_storage()
    {
        $this->cache->shouldReceive('get')->with('foo')->once()->andReturn(['foo' => 'bar']);

        $this->assertSame(['foo' => 'bar'], $this->storage->get('foo'));
    }

    /** @test */
    public function it_should_remove_the_item_from_storage()
    {
        $this->cache->shouldReceive('delete')->with('foo')->once()->andReturn(true);

        $this->assertTrue($this->storage->destroy('foo'));
    }

    /** @test */
    public function it_should_remove_all_items_from_storage()
    {
        $this->cache->shouldReceive('clean')->withNoArgs()->once();

        $this->storage->flush();
    }

    /** @test */
    public function it_should_add_the_item_to_tagged_storage()
    {
        $this->cache->shouldReceive('save')->with('foo', 'bar', 10)->once();

        $this->storage->add('foo', 'bar', 10);
    }

    /** @test */
    public function it_should_add_the_item_to_tagged_storage_forever()
    {
        $this->cache->shouldReceive('save')->with('foo', 'bar', 0)->once();

        $this->storage->forever('foo', 'bar');
    }

    /** @test */
    public function it_should_get_an_item_from_tagged_storage()
    {
        $this->cache->shouldReceive('get')->with('foo')->once()->andReturn(['foo' => 'bar']);

        $this->assertSame(['foo' => 'bar'], $this->storage->get('foo'));
    }

    /** @test */
    public function it_should_remove_the_item_from_tagged_storage()
    {
        $this->cache->shouldReceive('delete')->with('foo')->once()->andReturn(true);

        $this->assertTrue($this->storage->destroy('foo'));
    }

    /** @test */
    public function it_should_remove_all_tagged_items_from_storage()
    {
        $this->cache->shouldReceive('clean')->withNoArgs()->once();

        $this->storage->flush();
    }
}
