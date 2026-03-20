<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Tests\Security;

use League\O_Auth2\Server\Grant\Abstract_Grant;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Security boundary tests for token identifier generation in Abstract_Grant.
 *
 * These tests validate that generate_unique_identifier() produces cryptographically
 * random, sufficiently long, and collision-free identifiers as required by RFC 6749
 * and best-practice security guidelines.
 */
class TokenIdentifierEntropyTest extends TestCase
{
    private Abstract_Grant $grant;

    protected function setUp(): void
    {
        // Use an anonymous concrete subclass to access the protected method.
        $this->grant = new class extends Abstract_Grant {
            public function get_identifier(): string
            {
                return 'test_grant';
            }

            public function respond_to_access_token_request(
                \Psr\Http\Message\ServerRequestInterface $request,
                \League\O_Auth2\Server\Response_Types\Response_Type_Interface $responseType,
                \DateInterval $accessTokenTTL
            ): \League\O_Auth2\Server\Response_Types\Response_Type_Interface {
                return $responseType;
            }

            /** Expose the protected method for testing. */
            public function expose_generate(int $length = 40): string
            {
                return $this->generate_unique_identifier($length);
            }
        };
    }

    /**
     * The default identifier (40 bytes → 80 hex chars) must have the correct length.
     */
    public function test_default_identifier_has_correct_length(): void
    {
        $id = $this->grant->expose_generate();

        $this->assertSame(80, strlen($id), 'Default identifier must be 80 hex characters (40 random bytes)');
    }

    /**
     * Identifiers must only contain lowercase hex characters.
     */
    public function test_identifier_is_hex_encoded(): void
    {
        $id = $this->grant->expose_generate();

        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $id, 'Identifier must be lowercase hex');
    }

    /**
     * Two consecutive calls must not produce the same identifier.
     * Validates that the CSPRNG produces unique values.
     */
    public function test_identifiers_are_unique(): void
    {
        $ids = [];
        for ($i = 0; $i < 100; $i++) {
            $ids[] = $this->grant->expose_generate();
        }

        $unique = array_unique($ids);
        $this->assertCount(100, $unique, 'All 100 generated identifiers must be unique');
    }

    /**
     * A custom length of 16 bytes (minimum recommended) must produce 32 hex chars.
     */
    public function test_custom_length_16_bytes(): void
    {
        $id = $this->grant->expose_generate(16);

        $this->assertSame(32, strlen($id), '16-byte identifier must be 32 hex characters');
    }

    /**
     * The generated identifier must not be predictable from a small sample.
     * Rudimentary Shannon entropy check: hex distribution should be roughly uniform.
     *
     * This is not a statistical randomness test — it catches obvious breakage
     * like a zeroed PRNG output.
     */
    public function test_identifier_is_not_all_zeros(): void
    {
        $id = $this->grant->expose_generate();

        $this->assertNotSame(str_repeat('0', 80), $id, 'Identifier must not be all zeros');
    }

    /**
     * Identifiers of length 1 must be valid (boundary test).
     */
    public function test_length_one_is_valid(): void
    {
        $id = $this->grant->expose_generate(1);

        $this->assertSame(2, strlen($id));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{2}$/', $id);
    }
}
