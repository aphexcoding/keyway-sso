<?php

declare(strict_types=1);

namespace Keyway\Sso\Test\Support;

use yii\mutex\Mutex;

/**
 * A yii\mutex\Mutex whose lock can be made to fail on demand.
 *
 * Single-process tests cannot show a mutex doing its job, but they can show the adapter obeying
 * it: that the lock is taken around the write and given back afterwards, and - the assertion
 * that matters - that a lock which could not be taken ends the claim instead of letting it
 * proceed unprotected.
 */
final class RecordingMutex extends Mutex
{
    public bool $grant = true;

    /** @var list<string> */
    public array $acquired = [];

    /** @var list<string> */
    public array $released = [];

    /**
     * @param string $name
     * @param int $timeout
     */
    protected function acquireLock($name, $timeout = 0): bool
    {
        if (!$this->grant) {
            return false;
        }

        $this->acquired[] = (string)$name;

        return true;
    }

    /**
     * @param string $name
     */
    protected function releaseLock($name): bool
    {
        $this->released[] = (string)$name;

        return true;
    }
}
