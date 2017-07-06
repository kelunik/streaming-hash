<?php

namespace Kelunik\StreamingHash\Test;

use Amp\ByteStream\InMemoryStream;
use Amp\ByteStream\IteratorStream;
use Amp\ByteStream\Message;
use Amp\ByteStream\StreamException;
use Amp\Loop;
use Amp\PHPUnit\TestCase;
use Kelunik\StreamingHash\HashInputStream;
use Kelunik\StreamingHash\HmacInputStream;
use function Amp\Iterator\fromIterable;

class HashInputTest extends TestCase {
    public function test() {
        Loop::run(function () {
            $array = [\random_bytes(16), \random_bytes(35), \random_bytes(125)];
            $iterator = fromIterable($array, 1);
            $stream = new IteratorStream($iterator);
            $hashStream = new HashInputStream($stream, "sha1");
            yield new Message($hashStream);
            $hash = yield $hashStream->getHash();

            $this->assertNull(yield $hashStream->read());
            $this->assertSame(\sha1(implode("", $array)), $hash);
        });
    }

    public function testInvalidAlgorithm() {
        $this->expectException(StreamException::class);

        new HashInputStream(new InMemoryStream("true"), "random");
    }

    public function testGetters() {
        $stream = new HmacInputStream(new InMemoryStream("test"), "sha1", "test");
        $this->assertFalse($stream->isRawOutput());
        $this->assertSame("sha1", $stream->getAlgorithm());
        $this->assertSame("test", $stream->getKey());
    }
}
