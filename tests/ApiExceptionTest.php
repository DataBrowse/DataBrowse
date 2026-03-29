<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ApiExceptionTest extends TestCase {
    public function testApiExceptionCarriesHttpStatus(): void {
        $e = new ApiException('Not found', 404);
        $this->assertSame(404, $e->getHttpStatus());
        $this->assertSame('Not found', $e->getMessage());
    }

    public function testApiExceptionDefault400(): void {
        $e = new ApiException('Bad request');
        $this->assertSame(400, $e->getHttpStatus());
    }

    public function testApiExceptionExtends(): void {
        $e = new ApiException('Test', 422);
        $this->assertInstanceOf(\RuntimeException::class, $e);
        $this->assertInstanceOf(\Throwable::class, $e);
    }

    public function testApiExceptionWithPrevious(): void {
        $prev = new \Exception('original');
        $e = new ApiException('Wrapped', 500, $prev);
        $this->assertSame($prev, $e->getPrevious());
    }
}
