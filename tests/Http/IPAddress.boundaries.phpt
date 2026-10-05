<?php declare(strict_types=1);

/**
 * Test: Nette\Http\IPAddress classification at every fixed range boundary.
 */

use Nette\Http\IPAddress;
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


test('classification agrees with CIDR membership at boundaries and neighboring addresses', function () {
	$ranges = [
		'isPrivate' => ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'],
		'isLoopback' => ['127.0.0.0/8', '::1/128'],
		'isLinkLocal' => ['169.254.0.0/16', 'fe80::/10'],
		'isMulticast' => ['224.0.0.0/4', 'ff00::/8'],
		'isReserved' => [
			'0.0.0.0/8', '100.64.0.0/10', '192.0.0.0/24', '192.0.2.0/24', '198.18.0.0/15',
			'198.51.100.0/24', '203.0.113.0/24', '240.0.0.0/4', '255.255.255.255/32',
			'::/128', '64:ff9b::/96', '100::/64', '2001::/23', '2001:db8::/32',
		],
	];
	$addresses = [];
	foreach ($ranges as $blocks) {
		foreach ($blocks as $cidr) {
			[$network, $prefix] = explode('/', $cidr);
			$first = inet_pton($network);
			$last = $first;
			for ($bit = (int) $prefix; $bit < strlen($last) * 8; $bit++) {
				$byte = intdiv($bit, 8);
				$last[$byte] = chr(ord($last[$byte]) | (1 << (7 - $bit % 8)));
			}
			$binaries = [$first, $last];
			foreach ([[$first, -1], [$last, 1]] as [$binary, $delta]) {
				for ($i = strlen($binary) - 1; $i >= 0; $i--) {
					$value = ord($binary[$i]) + $delta;
					$binary[$i] = chr($value & 0xFF);
					if ($value >= 0 && $value <= 255) {
						$binaries[] = $binary;
						break;
					}
				}
			}
			foreach ($binaries as $binary) {
				$address = inet_ntop($binary);
				$addresses[] = $address;
				if (strlen($binary) === 4) {
					$addresses[] = '::ffff:' . $address;
					$addresses[] = '::' . $address;
				}
			}
		}
	}

	// Repeat across new instances to exercise both initialization and reuse of each cache.
	foreach ([1, 2] as $pass) {
		foreach (array_unique($addresses) as $address) {
			$ip = new IPAddress($address);
			$public = true;
			foreach ($ranges as $method => $blocks) {
				$expected = false;
				foreach ($blocks as $cidr) {
					$expected = $expected || $ip->isInRange($cidr);
				}
				Assert::same($expected, $ip->$method(), "$method: $address (pass $pass)");
				$public = $public && !$expected;
			}
			Assert::same($public, $ip->isPublic(), "isPublic: $address (pass $pass)");
		}
	}
});
