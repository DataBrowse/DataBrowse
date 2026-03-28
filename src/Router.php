<?php
declare(strict_types=1);

enum HttpMethod: string {
    case GET = 'GET';
    case POST = 'POST';
    case PUT = 'PUT';
    case DELETE = 'DELETE';
    case PATCH = 'PATCH';
}

final class Router {
    private array $routes = [];

    public function get(string $path, callable $handler): self {
        return $this->addRoute(HttpMethod::GET, $path, $handler);
    }

    public function post(string $path, callable $handler): self {
        return $this->addRoute(HttpMethod::POST, $path, $handler);
    }

    public function put(string $path, callable $handler): self {
        return $this->addRoute(HttpMethod::PUT, $path, $handler);
    }

    public function delete(string $path, callable $handler): self {
        return $this->addRoute(HttpMethod::DELETE, $path, $handler);
    }

    public function patch(string $path, callable $handler): self {
        return $this->addRoute(HttpMethod::PATCH, $path, $handler);
    }

    private function addRoute(HttpMethod $method, string $path, callable $handler): self {
        $pattern = preg_replace('/\{(\w+)\}/', '(?P<$1>[^/]+)', $path);
        $this->routes[] = [
            'method'  => $method,
            'pattern' => '#^' . $pattern . '$#',
            'handler' => $handler,
        ];
        return $this;
    }

    public function dispatch(string $method, string $uri): mixed {
        $httpMethod = HttpMethod::tryFrom(strtoupper($method));
        if ($httpMethod === null) {
            http_response_code(405);
            return ['error' => 'Method not allowed'];
        }

        foreach ($this->routes as $route) {
            if ($route['method'] !== $httpMethod) continue;
            if (!preg_match($route['pattern'], $uri, $matches)) continue;

            $params = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);
            return ($route['handler'])($params);
        }

        http_response_code(404);
        return ['error' => 'Route not found'];
    }
}
