<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class RouterTest extends TestCase {
    public function testSimpleGetRoute(): void {
        $router = new Router();
        $router->get('/api/test', fn() => ['success' => true]);
        $result = $router->dispatch('GET', '/api/test');
        $this->assertSame(['success' => true], $result);
    }

    public function testRouteWithParams(): void {
        $router = new Router();
        $router->get('/api/tables/{db}', fn(array $p) => ['db' => $p['db']]);
        $result = $router->dispatch('GET', '/api/tables/mydb');
        $this->assertSame(['db' => 'mydb'], $result);
    }

    public function testRouteWithMultipleParams(): void {
        $router = new Router();
        $router->get('/api/data/{db}/{table}', fn(array $p) => $p);
        $result = $router->dispatch('GET', '/api/data/mydb/users');
        $this->assertSame(['db' => 'mydb', 'table' => 'users'], $result);
    }

    public function testPostRoute(): void {
        $router = new Router();
        $router->post('/api/create', fn() => ['created' => true]);
        $result = $router->dispatch('POST', '/api/create');
        $this->assertSame(['created' => true], $result);
    }

    public function test404ForUnknownRoute(): void {
        $router = new Router();
        $router->get('/api/exists', fn() => ['ok' => true]);
        $result = $router->dispatch('GET', '/api/notexists');
        $this->assertArrayHasKey('error', $result);
    }

    public function testMethodFiltering(): void {
        $router = new Router();
        $router->get('/api/resource', fn() => ['method' => 'GET']);
        $router->post('/api/resource', fn() => ['method' => 'POST']);
        $this->assertSame(['method' => 'GET'], $router->dispatch('GET', '/api/resource'));
        $this->assertSame(['method' => 'POST'], $router->dispatch('POST', '/api/resource'));
    }

    public function testDeleteRoute(): void {
        $router = new Router();
        $router->delete('/api/items/{id}', fn(array $p) => ['deleted' => $p['id']]);
        $result = $router->dispatch('DELETE', '/api/items/42');
        $this->assertSame(['deleted' => '42'], $result);
    }
}
