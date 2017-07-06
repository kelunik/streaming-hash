<?php

namespace Kelunik\StreamingHash;

use Amp\ByteStream\InputStream;
use Amp\ByteStream\StreamException;
use Amp\Deferred;
use Amp\Promise;
use function Amp\call;

/**
 * Allows hashing of input streams.
 */
final class HashInputStream implements InputStream {
    private $source;
    private $algorithm;
    private $rawOutput;
    private $resource;
    private $hashDeferred;

    /**
     * @param InputStream $source Input stream to read data from.
     * @param string      $algorithm Hash function to use.
     * @param bool        $rawOutput Whether to output raw bytes or the hex encoding of it.
     *
     * @throws StreamException
     * @throws \Error
     *
     * @see http://php.net/manual/en/function.inflate-init.php
     */
    public function __construct(InputStream $source, string $algorithm, bool $rawOutput = false) {
        $this->source = $source;
        $this->algorithm = $algorithm;
        $this->rawOutput = $rawOutput;
        $this->hashDeferred = new Deferred;
        $this->resource = @\hash_init($algorithm);

        if ($this->resource === false) {
            throw new StreamException("Failed initializing hash context");
        }
    }

    /** @inheritdoc */
    public function read(): Promise {
        return call(function () {
            if ($this->resource === null) {
                return null;
            }

            $data = yield $this->source->read();

            // Needs a double guard, as stream might have been closed while reading
            if ($this->resource === null) {
                return null;
            }

            if ($data === null) {
                $this->hashDeferred->resolve(\hash_final($this->resource, $this->rawOutput));
                $this->close();

                return null;
            }

            \hash_update($this->resource, $data);

            return $data;
        });
    }

    /** @internal */
    private function close() {
        $this->resource = null;
        $this->source = null;
    }

    /**
     * Gets the used algorithm.
     *
     * @return string Algorithm specified on construction time.
     */
    public function getAlgorithm(): string {
        return $this->algorithm;
    }

    /**
     * Whether to output raw bytes or the hex encoding of it.
     *
     * @return bool
     */
    public function isRawOutput(): bool {
        return $this->rawOutput;
    }

    /**
     * Returns a promise resolving to the hash once the stream ends.
     *
     * @return Promise<string>
     */
    public function getHash(): Promise {
        return $this->hashDeferred->promise();
    }
}
