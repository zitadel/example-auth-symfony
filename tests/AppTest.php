<?php

declare(strict_types=1);

namespace App\Tests;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class AppTest extends WebTestCase
{
    public function testAppStarts(): void
    {
        $client = AppTest::createClient();
        $this->assertNotNull($client);
    }

    public function testHomePageLoads(): void
    {
        $client = AppTest::createClient();
        $client->request('GET', '/');
        $this->assertResponseIsSuccessful();
    }

    public function testSigninPageLoads(): void
    {
        $client = AppTest::createClient();
        $client->request('GET', '/auth/signin');
        $this->assertResponseIsSuccessful();
    }

    public function testProfileRedirectsWhenUnauthenticated(): void
    {
        $client = AppTest::createClient();
        $client->request('GET', '/profile');
        $this->assertResponseRedirects();
    }
}
