<?php

declare(strict_types=1);

use ComposerUnused\ComposerUnused\Configuration\Configuration;
use ComposerUnused\ComposerUnused\Configuration\NamedFilter;

return static function (Configuration $config): Configuration {
    $config->addNamedFilter(NamedFilter::fromString('ext-ctype'));
    $config->addNamedFilter(NamedFilter::fromString('ext-iconv'));
    $config->addNamedFilter(NamedFilter::fromString('symfony/asset'));
    $config->addNamedFilter(NamedFilter::fromString('symfony/console'));
    $config->addNamedFilter(NamedFilter::fromString('symfony/dotenv'));
    $config->addNamedFilter(NamedFilter::fromString('symfony/flex'));
    $config->addNamedFilter(NamedFilter::fromString('symfony/http-client'));
    $config->addNamedFilter(NamedFilter::fromString('symfony/runtime'));
    $config->addNamedFilter(NamedFilter::fromString('symfony/security-bundle'));
    $config->addNamedFilter(NamedFilter::fromString('symfony/twig-bundle'));
    $config->addNamedFilter(NamedFilter::fromString('symfony/yaml'));
    $config->addNamedFilter(NamedFilter::fromString('twig/extra-bundle'));
    $config->addNamedFilter(NamedFilter::fromString('twig/twig'));

    return $config;
};
