<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fluent\JWTAuth\Test\Http;

use CodeIgniter\Config\Services;
use CodeIgniter\Http\Request;
use Mockery;
use Fluent\JWTAuth\Contracts\Http\ParserInterface;
use Fluent\JWTAuth\Http\Parser\AuthHeaders;
use Fluent\JWTAuth\Http\Parser\Cookies;
use Fluent\JWTAuth\Http\Parser\InputSource;
use Fluent\JWTAuth\Http\Parser\HttpParser;
use Fluent\JWTAuth\Http\Parser\QueryString;
use Fluent\JWTAuth\Test\AbstractTestCase;

class ParserTest extends AbstractTestCase
{
    /** @test */
    public function it_should_return_the_token_from_the_authorization_header()
    {
        $request = Services::request(null, false);
        $request->setHeader('Authorization', 'Bearer foobar');

        $parser = new HttpParser($request);

        $parser->setChain([
            new AuthHeaders(),
            new Cookies(),
            new InputSource(),
            new QueryString(),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_prefixed_authentication_header()
    {
        $request = Services::request(null, false);
        $request->setHeader('Authorization', 'Custom foobar');

        $parser = new HttpParser($request);

        $parser->setChain([
           (new AuthHeaders())->setHeaderPrefix('Custom'),
            new Cookies(),
            new InputSource(),
            new QueryString(),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_authentication_header()
    {
        $request = Services::request(null, false);
        $request->setHeader('custom_authorization', 'Bearer foobar');

        $parser = new HttpParser($request);

        $parser->setChain([
            new QueryString,
            new InputSource,
            (new AuthHeaders)->setHeaderName('custom_authorization'),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_alt_authorization_headers()
    {
        $request1 = Services::request(null, false);
        $request1->setGlobal('server', ['HTTP_AUTHORIZATION' => 'Bearer foobar']);

        $request2 = Services::request(null, false);
        $request2->setGlobal('server', ['REDIRECT_HTTP_AUTHORIZATION' => 'Bearer foobarbaz']);

        $parser = new HttpParser($request1, [
            new AuthHeaders,
            new QueryString,
            new InputSource,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());

        $parser->setRequest($request2);
        $this->assertSame($parser->parseToken(), 'foobarbaz');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_not_strip_trailing_hyphens_from_the_authorization_header()
    {
        $request = Services::request(null, false);
        $request->setHeader('Authorization', 'Bearer foo-bar');

        $parser = new HttpParser($request);

        $parser->setChain([
            new QueryString,
            new InputSource,
            new AuthHeaders,
        ]);

        $this->assertSame($parser->parseToken(), 'foo-bar');
        $this->assertTrue($parser->hasToken());
    }

    /**
     * @test
     * @dataProvider whitespaceProvider
     */
    public function it_should_handle_excess_whitespace_from_the_authorization_header($whitespace)
    {
        $request = Services::request(null, false);
        $request->setHeader('Authorization', "Bearer{$whitespace}foobar{$whitespace}");

        $parser = new HttpParser($request);

        $parser->setChain([
            new QueryString,
            new InputSource,
            new AuthHeaders,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    public function whitespaceProvider()
    {
        return [
            'space' => [' '],
            'multiple spaces' => ['    '],
            'tab' => ["\t"],
            'multiple tabs' => ["\t\t\t"],
            'new line' => ["\n"],
            'multiple new lines' => ["\n\n\n"],
            'carriage return' => ["\r"],
            'carriage returns' => ["\r\r\r"],
            'mixture of whitespace' => ["\t \n \r \t \n"],
        ];
    }

    /** @test */
    public function it_should_return_the_token_from_query_string()
    {
        $request = Services::request(null, false);
        $request->setGlobal('get', ['token' => 'foobar']);

        $parser = new HttpParser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_query_string()
    {
        $request = Services::request(null, false);
        $request->setGlobal('get', ['custom_token_key' => 'foobar']);

        $parser = new HttpParser($request);
        $parser->setChain([
            new AuthHeaders,
            (new QueryString)->setKey('custom_token_key'),
            new InputSource,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_query_string_not_the_input_source()
    {
        $request = Services::request(null, false);
        $request->setGlobal('get', ['token' => 'foobar']);
        $request->setGlobal('post', ['token' => 'foobarbaz']);

        $parser = new HttpParser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_query_string_not_the_custom_input_source()
    {
        $request = Services::request(null, false);
        $request->setGlobal('get', ['custom_token_key' => 'foobar']);
        $request->setGlobal('post', ['custom_token_key' => 'foobarbaz']);

        $parser = new HttpParser($request);
        $parser->setChain([
            new AuthHeaders,
            (new QueryString)->setKey('custom_token_key'),
            (new InputSource)->setKey('custom_token_key'),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_input_source()
    {
        $request = Services::request(null, false);
        $request->setGlobal('post', ['token' => 'foobar']);

        $parser = new HttpParser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_input_source()
    {
        $request = Services::request(null, false);
        $request->setGlobal('post', ['custom_token_key' => 'foobar']);

        $parser = new HttpParser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            (new InputSource)->setKey('custom_token_key'),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_an_unencrypted_cookie()
    {
        $request = Services::request(null, false);
        $request->setGlobal('post', ['token' => 'foobar']);

        $parser = new HttpParser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
            new Cookies(false),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }


    /** @test */
    public function it_should_ignore_routeless_requests()
    {
        $request = Services::request(null, false);
        $request->setGlobal('get', ['foo' => 'bar']);

        $parser = new HttpParser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_return_null_if_no_token_in_request()
    {
        $request = Services::request(null, false);
        $request->setGlobal('get', ['foo' => 'bar']);

        $parser = new HttpParser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new InputSource,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_retrieve_the_chain()
    {
        $chain = [
            new AuthHeaders,
            new QueryString,
            new InputSource,
        ];

        $parser = new HttpParser(Services::request(null, false));
        $parser->setChain($chain);

        $this->assertSame($parser->getChain(), $chain);
    }

    /** @test */
    public function it_should_retrieve_the_chain_with_alias()
    {
        $chain = [
            new AuthHeaders,
            new QueryString,
            new InputSource,
        ];

        /* @var \CodeIgniter\Http\Request $request */
        $request = Mockery::mock(Request::class);

        $parser = new HttpParser($request);
        $parser->setChainOrder($chain);

        $this->assertSame($parser->getChain(), $chain);
    }

    /** @test */
    public function it_should_set_the_cookie_key()
    {
        $cookies = (new Cookies)->setKey('test');
        $this->assertInstanceOf(Cookies::class, $cookies);
    }

    /** @test */
    public function it_should_add_custom_parser()
    {
        $request = Services::request(null, false);
        $request->setGlobal('get', ['foo' => 'bar']);

        $customParser = Mockery::mock(ParserInterface::class);
        $customParser->shouldReceive('parse')->with($request)->andReturn('foobar');

        $parser = new HttpParser($request);
        $parser->addParser($customParser);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_add_multiple_custom_parser()
    {
        $request = Services::request(null, false);
        $request->setGlobal('get', ['foo' => 'bar']);

        $customParser1 = Mockery::mock(ParserInterface::class);
        $customParser1->shouldReceive('parse')->with($request)->andReturn(false);

        $customParser2 = Mockery::mock(ParserInterface::class);
        $customParser2->shouldReceive('parse')->with($request)->andReturn('foobar');

        $parser = new HttpParser($request);
        $parser->addParser([$customParser1, $customParser2]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }
}
