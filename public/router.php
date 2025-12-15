<?php

if (preg_match('/\.(svg|png|jpg|jpeg|gif|ico|css|js)$/', $_SERVER['REQUEST_URI'])) {
    return false;
}
require __DIR__ . '/index.php';
