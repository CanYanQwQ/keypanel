<?php

declare(strict_types=1);

require dirname(__DIR__).'/src/CardKey/Errors.php';
require dirname(__DIR__).'/src/CardKey/Models.php';
require dirname(__DIR__).'/src/CardKey/Signer.php';
require dirname(__DIR__).'/src/CardKey/TransportCrypto.php';

use CardKey\Signer;
use CardKey\TransportCrypto;

$body = '{"card_key":"ABCD-EFGH-JKMN-PQRS","device_id":"device-001"}';
$canonical = "POST\n/api/v1/verify\n1700000000\n00112233445566778899aabbccddeeff\nd4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb";
assert(Signer::canonicalRequest('POST', '/api/v1/verify', '1700000000', '00112233445566778899aabbccddeeff', $body) === $canonical);
assert(Signer::signRequest('sk_test_secret_for_vectors_do_not_use', 'POST', '/api/v1/verify', '1700000000', '00112233445566778899aabbccddeeff', $body) === 'cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e');
assert(bin2hex(TransportCrypto::deriveKey('sk_test_secret_for_vectors_do_not_use', 'ak_test_0000000000000000')) === 'bff2fbbc96525ad71f7e1492b39e1eb22fc76915f55a452dae9c7bd8e8ce8a2a');
assert(TransportCrypto::decrypt(['iv' => 'AAECAwQFBgcICQoL', 'data' => 'Dpzc19OrLLuiUzBnVjZ58nx01g==', 'tag' => 'OgQTxDEviBNBjrGdUcPfPw=='], 'sk_test_secret_for_vectors_do_not_use', 'ak_test_0000000000000000') === 'ABCD-EFGH-JKMN-PQRS');
fwrite(STDOUT, "PHP conformance vectors passed\n");
