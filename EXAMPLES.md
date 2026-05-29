# `sct` command use-case examples

The examples below use real log IDs from the cached log list.
Run `sct logs` to see all available logs and their IDs.

```sh
$ sct logs
ID  API TYPE  DESCRIPTION                                                   STATE
1   rfc6962   Google 'Argon2026h1' log                                      usable
2   rfc6962   Google 'Argon2026h2' log                                      usable
3   rfc6962   Google 'Argon2027h1'                                          usable
4   rfc6962   Google 'Xenon2026h1' log                                      usable
5   rfc6962   Google 'Xenon2026h2' log                                      usable
6   rfc6962   Google 'Xenon2027h1'                                          usable
7   rfc6962   Cloudflare 'Nimbus2026'                                       usable
8   rfc6962   Cloudflare 'Nimbus2027'                                       usable
9   rfc6962   DigiCert 'Wyvern2026h1'                                       usable
10  rfc6962   DigiCert 'Wyvern2026h2'                                       usable
11  rfc6962   DigiCert 'Wyvern2027h1'                                       usable
12  rfc6962   DigiCert 'Wyvern2027h2'                                       usable
13  rfc6962   DigiCert 'Sphinx2026h1'                                       usable
14  rfc6962   DigiCert 'Sphinx2026h2'                                       usable
15  rfc6962   DigiCert 'sphinx2027h1'                                       usable
16  rfc6962   DigiCert 'sphinx2027h2'                                       usable
17  rfc6962   Sectigo 'Mammoth2026h1'                                       readonly
18  rfc6962   Sectigo 'Mammoth2026h2'                                       readonly
19  rfc6962   Sectigo 'Sabre2026h1'                                         readonly
20  rfc6962   Sectigo 'Sabre2026h2'                                         readonly
21  rfc6962   Sectigo 'Elephant2026h1'                                      usable
22  rfc6962   Sectigo 'Elephant2026h2'                                      usable
23  rfc6962   Sectigo 'Elephant2027h1'                                      usable
24  rfc6962   Sectigo 'Elephant2027h2'                                      usable
25  rfc6962   Sectigo 'Tiger2026h1'                                         usable
26  rfc6962   Sectigo 'Tiger2026h2'                                         usable
27  rfc6962   Sectigo 'Tiger2027h1'                                         usable
28  rfc6962   Sectigo 'Tiger2027h2'                                         usable
29  rfc6962   Let's Encrypt 'Oak2026h1'                                     retired
30  rfc6962   Let's Encrypt 'Oak2026h2'                                     retired
31  static    Let's Encrypt 'Sycamore2026h1'                                usable
32  static    Let's Encrypt 'Sycamore2026h2'                                usable
33  static    Let's Encrypt 'Sycamore2027h1'                                usable
34  static    Let's Encrypt 'Sycamore2027h2'                                usable
35  static    Let's Encrypt 'Willow2026h1'                                  usable
36  static    Let's Encrypt 'Willow2026h2'                                  usable
37  static    Let's Encrypt 'Willow2027h1'                                  usable
38  static    Let's Encrypt 'Willow2027h2'                                  usable
39  rfc6962   TrustAsia 'log2026a'                                          usable
40  rfc6962   TrustAsia 'log2026b'                                          usable
41  rfc6962   TrustAsia 'HETU2027'                                          usable
42  static    TrustAsia Luoshu2027                                          usable
43  rfc6962   Bogus placeholder log to unbreak misbehaving CT libraries     retired
44  static    Geomys 'Tuscolo2026h1'                                        usable
45  static    Geomys 'Tuscolo2026h2'                                        usable
46  static    Geomys 'Tuscolo2027h1'                                        usable
47  static    Geomys 'Tuscolo2027h2'                                        usable
48  rfc6962   Bogus RFC6962 log to avoid breaking misbehaving CT libraries  retired
49  static    IPng Networks 'Halloumi2026h1'                                usable
50  static    IPng Networks 'Halloumi2026h2a'                               usable
51  static    IPng Networks 'Halloumi2027h1'                                usable
52  static    IPng Networks 'Halloumi2027h2'                                usable
53  static    IPng Networks 'Gouda2026h1'                                   usable
54  static    IPng Networks 'Gouda2026h2'                                   usable
55  static    IPng Networks 'Gouda2027h1'                                   usable
56  static    IPng Networks 'Gouda2027h2'                                   usable
```

Below are the examples when `--type` and `--interval`  option is specified.
`--type` is useful when a log of specific API type needs to be identified.
`--interval` shows temporal sharding interval ("START" and "END"), which helps to
check whether a certificate with a specific NotAfter value could be added to the logs.

```sh
$ sct logs --type static --interval
ID  API TYPE  DESCRIPTION                      STATE   START                 END
31  static    Let's Encrypt 'Sycamore2026h1'   usable  2025-12-18T00:00:00Z  2026-06-18T00:00:00Z
32  static    Let's Encrypt 'Sycamore2026h2'   usable  2026-06-18T00:00:00Z  2026-12-17T00:00:00Z
33  static    Let's Encrypt 'Sycamore2027h1'   usable  2026-12-17T00:00:00Z  2027-06-18T00:00:00Z
34  static    Let's Encrypt 'Sycamore2027h2'   usable  2027-06-18T00:00:00Z  2027-12-16T00:00:00Z
35  static    Let's Encrypt 'Willow2026h1'     usable  2025-12-17T00:00:00Z  2026-06-17T00:00:00Z
36  static    Let's Encrypt 'Willow2026h2'     usable  2026-06-17T00:00:00Z  2026-12-16T00:00:00Z
37  static    Let's Encrypt 'Willow2027h1'     usable  2026-12-16T00:00:00Z  2027-06-17T00:00:00Z
38  static    Let's Encrypt 'Willow2027h2'     usable  2027-06-17T00:00:00Z  2027-12-15T00:00:00Z
42  static    TrustAsia Luoshu2027             usable  2026-12-24T00:00:00Z  2028-01-08T00:00:00Z
44  static    Geomys 'Tuscolo2026h1'           usable  2026-01-01T00:00:00Z  2026-07-01T00:00:00Z
45  static    Geomys 'Tuscolo2026h2'           usable  2026-07-01T00:00:00Z  2027-01-01T00:00:00Z
46  static    Geomys 'Tuscolo2027h1'           usable  2027-01-01T00:00:00Z  2027-07-01T00:00:00Z
47  static    Geomys 'Tuscolo2027h2'           usable  2027-07-01T00:00:00Z  2028-01-01T00:00:00Z
49  static    IPng Networks 'Halloumi2026h1'   usable  2026-01-01T00:00:00Z  2026-07-01T00:00:00Z
50  static    IPng Networks 'Halloumi2026h2a'  usable  2026-07-01T00:00:00Z  2027-01-01T00:00:00Z
51  static    IPng Networks 'Halloumi2027h1'   usable  2027-01-01T00:00:00Z  2027-07-01T00:00:00Z
52  static    IPng Networks 'Halloumi2027h2'   usable  2027-07-01T00:00:00Z  2028-01-01T00:00:00Z
53  static    IPng Networks 'Gouda2026h1'      usable  2026-01-01T00:00:00Z  2026-07-01T00:00:00Z
54  static    IPng Networks 'Gouda2026h2'      usable  2026-07-01T00:00:00Z  2027-01-01T00:00:00Z
55  static    IPng Networks 'Gouda2027h1'      usable  2027-01-01T00:00:00Z  2027-07-01T00:00:00Z
56  static    IPng Networks 'Gouda2027h2'      usable  2027-07-01T00:00:00Z  2028-01-01T00:00:00Z
```

## Tool-specific commands

### `logs`

```sh
# List all logs
sct logs

# List only usable logs
sct logs --state usable

# List usable Static CT API logs with their temporal shard intervals
sct logs --state usable --type static --interval

# Re-fetch the log list from Google and refresh the local cache
sct logs --refresh
```

### `get-sct`

```sh
# Extract SCT extensions from a local PEM file
sct get-sct --pem ./cert.pem

# Fetch a certificate from a URL and extract its SCT extensions
sct get-sct --url https://example.com

# Skip TLS verification when fetching from an internal or self-signed endpoint
# (this pattern would be useful only when the endpoint's configuration is incomplete and verification fails)
sct get-sct --url https://internal.example.com --insecure
```

Below are example outputs.
Note that "log_id_description" is not included in raw SCTs. This field is appended by this tool
by looking up the "log_id" in cached logs.

```sh
# Two RFC 6962 SCTs by `--url` option
$ sct get-sct --url https://example.com
[
  {
    "version": 0,
    "log_id": "yKPEf8ezrbk1awE/anoSbeM6TkOlxkb5l605dZkdz5o=",
    "log_id_description": "Sectigo 'Tiger2026h2'",
    "timestamp": "2026-04-02T21:28:58.287Z"
  },
  {
    "version": 0,
    "log_id": "lE5Dh/rswe+B8xkkJqgYZQHH0184AgE/cmd9VTcuGdg=",
    "log_id_description": "DigiCert 'Sphinx2026h2'",
    "timestamp": "2026-04-02T21:28:58.256Z"
  }
]
```

```sh
# The same by `--pem` option
$ sct get-sct --pem ./cert.pem
[
  {
    "version": 0,
    "log_id": "yKPEf8ezrbk1awE/anoSbeM6TkOlxkb5l605dZkdz5o=",
    "log_id_description": "Sectigo 'Tiger2026h2'",
    "timestamp": "2026-04-02T21:28:58.287Z"
  },
  {
    "version": 0,
    "log_id": "lE5Dh/rswe+B8xkkJqgYZQHH0184AgE/cmd9VTcuGdg=",
    "log_id_description": "DigiCert 'Sphinx2026h2'",
    "timestamp": "2026-04-02T21:28:58.256Z"
  }
]
```

```sh
# Two SCTs: the former is Static CT API SCT and the latter is RFC 6962 SCT
# '"extension_type": 0' means "leaf_index" extension type and the "extension_value" is leaf index value.
# Leaf index value exists only in Static CT API SCT.
$ sct get-sct --url https://letsencrypt.org
[
  {
    "version": 0,
    "log_id": "Rq+GPTs+5Z+ld96oJF02sNntIqIj9GF3QSKUUu6VUF8=",
    "log_id_description": "Geomys 'Tuscolo2026h2'",
    "timestamp": "2026-05-07T17:13:07.93Z",
    "ct_extensions": [
      {
        "extension_type": 0,
        "extension_length": 5,
        "extension_value": 99888173
      }
    ]
  },
  {
    "version": 0,
    "log_id": "r2eIO1ewTt2Pptl+9i6o64EKx3Fg8CReVdYML+eFhzo=",
    "log_id_description": "Sectigo 'Elephant2026h2'",
    "timestamp": "2026-05-07T17:13:08.116Z"
  }
]
```

### `audit-path`

```sh
# Simulate the audit path for leaf index 5 in a tree of size 8
sct audit-path --index 5 --size 8

# Larger tree: leaf index 1000000 in a tree of 5000000 leaves
sct audit-path --index 1000000 --size 5000000
```

Below is an example output.

```sh
# This example shows that leaf nodes [4,5), [6,8), and [0, 4) are required to verify
# that the leaf node of index 5 is included in the tree.
$ sct audit-path --index 5 --size 8
{
  "leaf_index": 5,
  "tree_size": 8,
  "nodes": [
    {
      "start": 4,
      "end": 5
    },
    {
      "start": 6,
      "end": 8
    },
    {
      "start": 0,
      "end": 4
    }
  ]
}
```

### `audit-tile`

```sh
# Simulate which tiles would be fetched for leaf index 5 in a tree of size 8
sct audit-tile --index 5 --size 8

# Larger tree: leaf index 1000000 in a tree of 5000000 leaves
sct audit-tile --index 1000000 --size 5000000
```

Below is an example output.

```sh
# This example shows that a partial tile of path 0/000.p/8 is required to verify that
# the leaf node of index 5 is included the tree.
# In the tile, 1 hash entry from offset 5, 1 hash entry from offset 4, 2 entries from offset 6,
# and 4 entries from offset 0 (from the beginning) are used for the verification.
$ sct audit-tile --index 5 --size 8
{
  "leaf_index": 5,
  "tree_size": 8,
  "tiles": {
    "tile/0/000.p/8": [
      {
        "offset": 5,
        "count": 1
      },
      {
        "offset": 4,
        "count": 1
      },
      {
        "offset": 6,
        "count": 2
      },
      {
        "offset": 0,
        "count": 4
      }
    ]
  }
}
```

### `version`

```sh
sct version
```

Below is an example output.

```sh
$ sct version
0.6.0
```

## Static CT API commands

### `checkpoint`

```sh
# Fetch the current signed checkpoint from Let's Encrypt 'Sycamore2026h1' (ID 31)
sct checkpoint --log 31
```

Below is an example output.

```sh
$ sct checkpoint --log 31
{
  "origin": "log.sycamore.ct.letsencrypt.org/2026h1",
  "tree_size": 917123884,
  "root_hash": "cYHqLU+MCbdAdXYAdLJhoNnPFqByTarydojPYOxV028=",
  "signed_notes": [
    {
      "key_name": "grease.invalid",
      "signature": {
        "unknown": "OgnEzHDvIGzhotxHYDYM5x5ARKIckrmPse8ZsGnqAvJzoLVqKVara2Q2+/JcUh3yUhCEzs7DsSQGvRluuyIZkW1g3cjUrVdiiqDnoc58phM8gGbpFwQ="
      }
    },
    {
      "key_name": "log.sycamore.ct.letsencrypt.org/2026h1",
      "signature": {
        "key_id": "d831bd7b",
        "signature": "zCLl5MTGAIdCWNav3kng8G9FP6cQFeS6v4xGejGwqtl+ntJEFuOTaJof4+GdNGuG2QeOgu1SPViQBO62o0Alb4IUvzjrONGUUoQCj1sc"
      }
    },
    {
      "key_name": "log.sycamore.ct.letsencrypt.org/2026h1",
      "signature": {
        "key_id": "104b9ebf",
        "signature": "AAABnnMGUC0EAwBGMEQCIGYmKllbHO130lM+3owjPX6bh4q/cs2qRaHCtalfmQN/AiBQNN951DmH9UMszVAir92HYGjMuQU8sHNegPq2li8UlA=="
      }
    },
    {
      "key_name": "log.sycamore.ct.letsencrypt.org/2026h1",
      "signature": {
        "key_id": "77022354",
        "signature": "dR9qHY1J2lg5QWvm3Yu2lwDoKaxbJht7vVzFpHlSp49jblpflW2HJb76MgP3LRwD8pxT15BkeBUeE89eZyY/Aw=="
      }
    }
  ]
}
```

### `data`

```sh
# Fetch and print the data tile entry at leaf index 1234567 from log 31
sct data --log 31 --index 1234567

# Fetch the entry and save all tile entries to /tmp
sct data --log 31 --index 1234567 --out /tmp
```

Below is an example output.

```sh
# "x509" type data entry
$ sct data --log 45 --index 130438194
{
  "timestamp": "2026-05-27T09:13:28.529Z",
  "entry_type": "x509",
  "leaf_index": 130438194,
  "fps_chain": [
    "2964fd3210ea68faa2b4a849b36243d33f74429d1b43ce019e7b154eac7759ba",
    "5d1bc399274e649e1c72697de91a54ad725088c5221cb61e17ee9c290bc42a92",
    "ba06d3d3e348fce7478cc84b422d0e638e9e221ef1a0b53adc14cc70e04b8ab8",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"
  ],
  "certificate": {
    "version": 3,
    "serial": "6520589ef17eb55c664433f29f2e684a",
    "sig_alg": "ECDSA-SHA256",
    "issuer": "CN=Cloudflare TLS Issuing ECC CA 1,O=CLOUDFLARE\\, INC.,C=US",
    "not_before": "2026-04-02T21:18:57Z",
    "not_after": "2026-07-01T21:24:46Z",
    "subject": "CN=example.com",
    "pubkey_alg": "ECDSA",
    "dns_names": [
      "example.com",
      "*.example.com"
    ],
    "aki": "9cc409724718177ba71a89b39235d5e1038cfe92",
    "policies": [
      "2.23.140.1.2.1",
      "1.3.6.1.4.1.38064.1.3.1.1"
    ],
    "key_usage": [
      "digitalSignature(00000001)"
    ],
    "ext_key_usage": [
      "serverAuth(1.3.6.1.5.5.7.3.1)"
    ]
  }
}
```

```sh
# "precert" type data entry
# Note that output below is illustrative and not a real example
$ sct data --log 99 --index 12345
{
  "timestamp": "2026-01-16T10:12:34.56Z",
  "entry_type": "precert",
  "leaf_index": 12345,
  "issuer_key_hash": "52f832c0298562c7ebf80a56ea3c80c47491848cd45efd966fac7a1dc9a8ba8a",
  "fps_chain": [
    "59cc6bad2c569e866065cc3e88179fd857a550b4b66671a3bb89e680d4a1ffd4",
    "1a460f8353f422f3bf93f79806a44bb024c9b10b16f83a48df5abefd5c18e818"
  ],
  "certificate": {
    "version": 3,
    "serial": "11112222333344445555666677778888",
    "sig_alg": "ECDSA-SHA256",
    "issuer": "CN=EXAMPLE TLS CA 1,O=Example Inc.,C=US",
    "not_before": "2026-01-16T10:12:34Z",
    "not_after": "2026-04-16T10:12:34Z",
    "subject": "CN=example.com",
    "pubkey_alg": "ECDSA",
    "ski": "e5a7bb48ce59abfc950aa06f76ca63c8ce3c7217",
    "dns_names": [
      "example.com",
      "*.example.com"
    ],
    "aki": "3b8712602bdfc7146e6b0cca69b5937eb3baade4",
    "policies": [
      "2.23.140.1.2.1"
    ],
    "key_usage": [
      "digitalSignature(00000001)"
    ],
    "ext_key_usage": [
      "serverAuth(1.3.6.1.5.5.7.3.1)"
    ]
  }
}
```

### `audit`

```sh
# Verify inclusion of leaf index 1234567 in Let's Encrypt 'Sycamore2026h1' (ID 31)
sct audit --log 31 --index 1234567

# Use --debug to see which tiles are fetched and which hashes are computed
sct --debug audit --log 31 --index 1234567
```

Below is an example output.
Some portions are omitted from the real result for brevity.

```sh
$ sct audit --log 31 --index 1234567
{
  "timestamp": "2026-05-29T09:19:05.861195586Z",
  "origin": "log.sycamore.ct.letsencrypt.org/2026h1",
  "verification_success": true,
  "audit_path": {
    "leaf_index": 1234567,
    "tree_size": 917124109,
    "nodes": [
      {
        "start": 1234566,
        "end": 1234567
      },
      ...
      {
        "start": 536870912,
        "end": 917124109
      }
    ]
  },
  "tiles": [
    {
      "path": "tile/3/000.p/54",
      "indices": [
        {
          "offset": 1,
          "count": 1
        },
        ...
        {
          "offset": 52,
          "count": 2
        }
      ]
    },
    ...
    {
      "path": "tile/2/000",
      "indices": [
        {
          "offset": 19,
          "count": 1
        },
        {
          "offset": 16,
          "count": 2
        },
        {
          "offset": 20,
          "count": 4
        },
        {
          "offset": 24,
          "count": 8
        },
        {
          "offset": 0,
          "count": 16
        },
        {
          "offset": 32,
          "count": 32
        },
        {
          "offset": 64,
          "count": 64
        },
        {
          "offset": 128,
          "count": 128
        }
      ]
    }
  ]
}
```

## RFC 6962 commands

### `get-sth`

```sh
# Fetch the signed tree head from Google 'Argon2026h1' (ID 1)
sct get-sth --log 1
```

Below is an example output.

```sh
$ sct get-sth --log 1
{
  "tree_size": 2786064990,
  "timestamp": "2026-05-29T09:20:22.443Z",
  "sha256_root_hash": "5T/1rNQeIwT9yha9ZkpQAQaro+6jIUAe9ui4aN0su+g=",
  "tree_head_signature": "BAMARzBFAiEAtyoAmkGOC7lyfgTFodAnm3GqBlOuvrMSkT4aEag/TQwCIAG6wi+xEDApTNoUb2QFCLg+PX5dOuFZHRrFreKD8gas"
}
```

### `get-proof-by-hash`

```sh
# Verify inclusion for all SCTs in a local certificate (issuer cert required)
sct get-proof-by-hash --pem ./leaf.pem --iss ./issuer.pem

# Fetch certificate from a URL and verify inclusion for all its SCTs
sct get-proof-by-hash --url https://example.com

# Verify using a leaf hash from get-entry-and-proof output (log ID required)
sct get-proof-by-hash --log 1 --hash 8J1FpPMFQnz8ol7bpDlxiEGiMdFMSEiWL+AVgkwP9/Y=
```

Below is an example output.

```sh
$ sct get-proof-by-hash --pem ./leaf.pem --iss ./issuer.pem
[
  {
    "fetched_at": "2026-05-29T13:18:13.384807547Z",
    "verification_success": true,
    "log": {
      "id": 26,
      "operator": "Sectigo",
      "description": "Sectigo 'Tiger2026h2'",
      "log_id": "yKPEf8ezrbk1awE/anoSbeM6TkOlxkb5l605dZkdz5o=",
      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfJFUD/FRkonvZIA9ZT1J3yvA4EpSp3innbIVpMTDR1oCe5vguapheQ7wYiWaCES1EL1B+2BEC+P5bUfwF44lnA==",
      "state": "usable",
      "api_type": "rfc6962",
      "start_inclusive": "2026-07-01T00:00:00Z",
      "end_exclusive": "2027-01-01T00:00:00Z",
      "url": "https://tiger2026h2.ct.sectigo.com/"
    },
    "tree_size": 956082840,
    "root_hash": "Je7mpFk4PhHogfpDRSlBjxB9Hs1rPZ0c5feyncfaKlE=",
    "leaf_hash": "BKk5qZDL4tsT+/kKYEKhrL/Dg9kzVt7zvDWKB6vqqBs=",
    "audit_proof": {
      "leaf_index": 187057165,
      "audit_path": [
        "nHRLMIdJ7BSVa17Xb53y1WXCa3/UKmWhCUxWyY/4B+Y=",
        "5fX70bs/KE73+pYxrUMnYmEdOpbUIVuuDm92PU6xq90=",
        "j4liHWW312RyO40l1KzYIvkjqZpz1dOHBiuA8n8tJgA=",
        ...
      ]
    }
  },
  {
    "fetched_at": "2026-05-29T13:18:15.126446756Z",
    "verification_success": true,
    "log": {
      "id": 14,
      "operator": "DigiCert",
      "description": "DigiCert 'Sphinx2026h2'",
      "log_id": "lE5Dh/rswe+B8xkkJqgYZQHH0184AgE/cmd9VTcuGdg=",
      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEquD0JkRQT/2inuaA4HC1sc6UpfiXgURVQmQcInmnZFnTiZMhZvsJgWAfYlU0OIykOC6slQzr7U9kvEVC9wZ6zQ==",
      "state": "usable",
      "api_type": "rfc6962",
      "start_inclusive": "2026-07-01T00:00:00Z",
      "end_exclusive": "2027-01-01T00:00:00Z",
      "url": "https://sphinx.ct.digicert.com/2026h2/"
    },
    "tree_size": 818556492,
    "root_hash": "yT8PL4gL1OV28U3mRzJtJT84xlRTPNr/9/NVycRL49Y=",
    "leaf_hash": "VgCVMwOmBPi5VBaaWK/JbesmDqiwwY9xsbd5QJjKsoY=",
    "audit_proof": {
      "leaf_index": 255905285,
      "audit_path": [
        "ZwM99AEOZlAyeuXOPeTX3HG0rqMguBfUie18pNh2bg8=",
        "xRoEeff4PLvecUqnA3/GSDpsvGK5kym9+MYrCis8BHY=",
        "uCAy23A2Y2grMLhgxIGBfoVphCrNz+Gmsdi+3aiLgwA=",
        ...
      ]
    }
  }
]
```

### `get-entries`

```sh
# Fetch only the entry at leaf index 1560 from Cloudflare 'Nimbus2026' (ID 7)
sct get-entries --log 7 --index 1560

# Fetch 4 entries: indices 1560 through 1563
sct get-entries --log 7 --index 1560 --offset 3
```

Below is an example output.

```sh
$ sct get-entries --log 7 --index 1560
{
  "log": {
    "id": 7,
    "operator": "Cloudflare",
    "description": "Cloudflare 'Nimbus2026'",
    "log_id": "yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc=",
    "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2FxhT6xq0iCATopC9gStS9SxHHmOKTLeaVNZ661488Aq8tARXQV+6+jB0983v5FkRm4OJxPqu29GJ1iG70Ahow==",
    "state": "usable",
    "api_type": "rfc6962",
    "start_inclusive": "2026-01-01T00:00:00Z",
    "end_exclusive": "2027-01-01T00:00:00Z",
    "url": "https://ct.cloudflare.com/logs/nimbus2026/"
  },
  "entries": [
    {
      "leaf_index": 1560,
      "leaf_input": {
        "version": 0,
        "leaf_type": 0,
        "timestamped_entry": {
          "timestamp": "2024-09-11T03:17:58.525Z",
          "entry_type": 0,
          "asn1cert": {
            "version": 3,
            "serial": "61db01132fc28",
            "sig_alg": "SHA256-RSA",
            "issuer": "CN=Merge Delay Intermediate 1,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
            "not_before": "2024-07-20T16:11:40Z",
            "not_after": "2026-08-02T08:30:33Z",
            "subject": "SERIALNUMBER=1721491900267560,O=Google Certificate Transparency,L=London,C=GB",
            "pubkey_alg": "RSA",
            "ski": "e09572c00fbc696b2dd5d55fbd3f6769248bf3a8",
            "dns_names": [
              "flowers-to-the-world.com"
            ],
            "aki": "e93c04e1802fc284132d26709ef2fd1acfaafec6",
            "ext_key_usage": [
              "serverAuth(1.3.6.1.5.5.7.3.1)"
            ]
          },
          "ct_extensions": 0
        }
      },
      "extra_data": [
        {
          "version": 3,
          "serial": "1001",
          "sig_alg": "SHA1-RSA",
          "issuer": "CN=Merge Delay Monitor Root,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
          "not_before": "2014-07-17T12:26:30Z",
          "not_after": "2019-07-16T12:26:30Z",
          "subject": "CN=Merge Delay Intermediate 1,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
          "pubkey_alg": "RSA",
          "ski": "e93c04e1802fc284132d26709ef2fd1acfaafec6",
          "aki": "f35f7b7549e37841396a20b67c6b4c5cc93d5841"
        },
        {
          "version": 3,
          "serial": "9ed3ccb1d12ca272",
          "sig_alg": "SHA1-RSA",
          "issuer": "CN=Merge Delay Monitor Root,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
          "not_before": "2014-07-17T12:05:43Z",
          "not_after": "2041-12-02T12:05:43Z",
          "subject": "CN=Merge Delay Monitor Root,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
          "pubkey_alg": "RSA",
          "ski": "f35f7b7549e37841396a20b67c6b4c5cc93d5841",
          "aki": "f35f7b7549e37841396a20b67c6b4c5cc93d5841"
        }
      ]
    }
  ]
}
```

### `get-entry-and-proof`

```sh
# Fetch entry at index 1560 and its audit path based on tree size 2000000
sct get-entry-and-proof --log 1 --index 1560 --size 2000000
```

Below are example outputs.

```sh
# This is RFC 6962 API, so "ct_extensions" under response.timestamped_entry field is empty (0)
$ sct get-entry-and-proof --log 1 --index 1560 --size 2000000
{
  "fetched_at": "2026-05-29T13:32:05.350616824Z",
  "log": {
    "id": 1,
    "operator": "Google",
    "description": "Google 'Argon2026h1' log",
    "log_id": "DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE=",
    "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB/we6GOO/xwxivy4HhkrYFAAPo6e2nc346Wo2o2U+GvoPWSPJz91s/xrEvA3Bk9kWHUUXVZS5morFEzsgdHqPg==",
    "state": "usable",
    "api_type": "rfc6962",
    "start_inclusive": "2026-01-01T00:00:00Z",
    "end_exclusive": "2026-07-01T00:00:00Z",
    "url": "https://ct.googleapis.com/logs/us1/argon2026h1/"
  },
  "leaf_hash": "uMrzi+sidjHhEH4/I88g7mbRXh3E10/FC44a4iS3N6Q=",
  "response": {
    "leaf_input": {
      "version": 0,
      "leaf_type": 0,
      "timestamped_entry": {
        "timestamp": "2024-07-20T08:32:43.945Z",
        "entry_type": 1,
        "precert": {
          "issuer_key_hash": "e37689003073a0c649cc656de946c03174d25c566fe3c3805b846f5236943798",
          "tbs_certificate": {
            "version": "0x02",
            "serial_number": "61da9a7e790c6",
            "signature_algorithm": "1.2.840.113549.1.1.11",
            "issuer": "CN=Merge Delay Intermediate 1,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
            "not_before": "2024-07-20T08:32:43Z",
            "not_after": "2026-02-01T06:58:16Z",
            "subject": "SERIALNUMBER=1721464363913414,O=Google Certificate Transparency,L=London,C=GB",
            "subject_public_key_info": {
              "algorithm_identifier": "1.2.840.113549.1.1.1",
              "public_key": "MIIBCgKCAQEA0XAHEd45+3CXY3sKAgwRZFxaBQKpkcSZA3BgJJro1THGcj0z25CTr46+hBugMZWE1iOiuiT6GTJPopyScNLxuFDJtZ5lIuNKXSkRowq/+RInC2BUVFhrL7Y9J80dKuj7amyMLysol0XbPOON4aEnklcIh4ThUYEq66XW0YLv2C87sQ/qZwpotZB8+2re+Yu6DIUckwXKkiya0xrT9crULBhG1iy3zxAcBnI7e0kW6PsWP2nHxoyJ7ajrLNveSgfDuNNhk6S32b2wGjoqxC3YaJJNUseADw11ox7/990u14L5g5sJUKpUDCqZgWEJUCuvo8TbTuMhZJOexuKEovE6/QIDAQAB"
            },
            "extensions": [
              {
                "oid": "2.5.29.37",
                "critical": false,
                "value": "MAoGCCsGAQUFBwMB"
              },
              {
                "oid": "2.5.29.17",
                "critical": false,
                "value": "MBqCGGZsb3dlcnMtdG8tdGhlLXdvcmxkLmNvbQ=="
              },
              {
                "oid": "2.5.29.19",
                "critical": true,
                "value": "MAA="
              },
              {
                "oid": "2.5.29.35",
                "critical": false,
                "value": "MBaAFOk8BOGAL8KEEy0mcJ7y/RrPqv7G"
              },
              {
                "oid": "2.5.29.14",
                "critical": false,
                "value": "BBR2bo8X35ZaDGhE1kCBCxuiLvWUxQ=="
              }
            ]
          }
        },
        "ct_extensions": 0
      }
    },
    "extra_data": [
      {
        "version": 3,
        "serial": "61da9a7e790c6",
        "sig_alg": "SHA256-RSA",
        "issuer": "CN=Merge Delay Intermediate 1,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
        "not_before": "2024-07-20T08:32:43Z",
        "not_after": "2026-02-01T06:58:16Z",
        "subject": "SERIALNUMBER=1721464363913414,O=Google Certificate Transparency,L=London,C=GB",
        "pubkey_alg": "RSA",
        "ski": "766e8f17df965a0c6844d640810b1ba22ef594c5",
        "dns_names": [
          "flowers-to-the-world.com"
        ],
        "aki": "e93c04e1802fc284132d26709ef2fd1acfaafec6",
        "ext_key_usage": [
          "serverAuth(1.3.6.1.5.5.7.3.1)"
        ]
      },
      {
        "version": 3,
        "serial": "1001",
        "sig_alg": "SHA1-RSA",
        "issuer": "CN=Merge Delay Monitor Root,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
        "not_before": "2014-07-17T12:26:30Z",
        "not_after": "2019-07-16T12:26:30Z",
        "subject": "CN=Merge Delay Intermediate 1,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
        "pubkey_alg": "RSA",
        "ski": "e93c04e1802fc284132d26709ef2fd1acfaafec6",
        "aki": "f35f7b7549e37841396a20b67c6b4c5cc93d5841"
      },
      {
        "version": 3,
        "serial": "9ed3ccb1d12ca272",
        "sig_alg": "SHA1-RSA",
        "issuer": "CN=Merge Delay Monitor Root,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
        "not_before": "2014-07-17T12:05:43Z",
        "not_after": "2041-12-02T12:05:43Z",
        "subject": "CN=Merge Delay Monitor Root,OU=Certificate Transparency,O=Google UK Ltd.,ST=London,C=GB",
        "pubkey_alg": "RSA",
        "ski": "f35f7b7549e37841396a20b67c6b4c5cc93d5841",
        "aki": "f35f7b7549e37841396a20b67c6b4c5cc93d5841"
      }
    ],
    "audit_path": [
      "H/pkzSdqok2ggC9n/RY4Ja+AZPhdJ//rEbsr4l/lUjY=",
      "QCE7kqUUL+4S1070zT+ndGqH+iudWCmSIbLfLvPGs54=",
      "r1J0ZhWoyFAz1geNBYqKEMtRGBQ6mgYRDFm38lxvjNs=",
      "ijPhdqLOISnC5iha2jAgj9FRVJQLWsTUIYvP8IDJw0k=",
      "7V9KsWpFmlxL7xseB6hYj4ox1oWWthzElalEB27eQfs=",
      "+2wDmBO+yU5AGUhpECWBYlNzedlHIyjkwDA81XqsltY=",
      "F3F6CwdfLswoniSldl7mOwtKTfSdoW5DKEZWmBXsipw=",
      "wwAxnNbWQbZ9d7cUtOjo/ojnW9kCBePYizolnbep1UU=",
      "mcexQENiHApIf6dBYxaRLTdSGhvPSIpmqal6O1EMSt4=",
      "czfVjstD9eYRLLP3m7FkEbA1hBt6R7hqZ7jnFUMWzAk=",
      "L+Zh06JJqGSLNzpY9FJDxEv8QxmKZ3ipIb6zjCOTvh8=",
      "GHxkz3qhkETuqYOYqqkQEKusNf9HZ62F2MX2JfIV1fw=",
      "SZ1XQk1Wera/vVS8nYYM4qdPd4V+wkCYPuPJSTHeOok=",
      "9Gy/cPkJ1hQb68twvYKCogliv3Um4HpMIJF9lVXnvVo=",
      "T+zdYdoX7Uas2thMgGZig6BAR08R5+k7qCuTLTonTmE=",
      "b2Ya2SJhgRC0vFsF1LwovQYZ9f1V6eAs0hkqZTVslcQ=",
      "CwPwuoOTkW3D6KuQCM4CuRMnK75cYh/sfo0MIeKYyQQ=",
      "OvfVZcY+jAVeUSXl4VaIuXPd7OrIN1ieYLZxxn1UxBs=",
      "0JqDMDUeF/Mw5pyuVcwxa8G+a1hor0EnSxGmOE/Ok1c=",
      "wf72RG1Ie25xvZl7uszXJzTFfLo0Wp0Zk9LOLVA5Bfs=",
      "E6T5Y97XjY3QiZ6mHwpEdlkUyYZaYALN+dn3YCJdnQA="
    ]
  }
}
```

The `leaf_hash` in the output can be passed to `get-proof-by-hash --hash` to verify inclusion:

```sh
$ sct get-proof-by-hash --log 1 --hash "uMrzi+sidjHhEH4/I88g7mbRXh3E10/FC44a4iS3N6Q="
{
  "fetched_at": "2026-05-29T09:46:14.282455513Z",
  "verification_success": true,
  "log": {
    "id": 1,
    "operator": "Google",
    "description": "Google 'Argon2026h1' log",
    "log_id": "DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE=",
    "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB/we6GOO/xwxivy4HhkrYFAAPo6e2nc346Wo2o2U+GvoPWSPJz91s/xrEvA3Bk9kWHUUXVZS5morFEzsgdHqPg==",
    "state": "usable",
    "api_type": "rfc6962",
    "start_inclusive": "2026-01-01T00:00:00Z",
    "end_exclusive": "2026-07-01T00:00:00Z",
    "url": "https://ct.googleapis.com/logs/us1/argon2026h1/"
  },
  "tree_size": 2786073204,
  "root_hash": "3AC9NvFKwt4/m/P4jUvoRKwIujy4ZSZ+exxHf059V7Y=",
  "leaf_hash": "uMrzi+sidjHhEH4/I88g7mbRXh3E10/FC44a4iS3N6Q=",
  "audit_proof": {
    "leaf_index": 1560,
    "audit_path": [
      "H/pkzSdqok2ggC9n/RY4Ja+AZPhdJ//rEbsr4l/lUjY=",
      "QCE7kqUUL+4S1070zT+ndGqH+iudWCmSIbLfLvPGs54=",
      "r1J0ZhWoyFAz1geNBYqKEMtRGBQ6mgYRDFm38lxvjNs=",
      ...
    ]
  }
}
```

## RFC 6962 and Static CT API commands

### `get-roots`

```sh
# Fetch accepted root certificates from Google 'Argon2026h1' (RFC 6962, ID 1)
sct get-roots --log 1

# Fetch accepted root certificates from Let's Encrypt 'Sycamore2026h1' (Static CT, ID 31)
sct get-roots --log 31
```

Below is a snippet of an example output.

```sh
# "raw" field is Base64-encoded DER data of the root certificate
$ sct get-roots --log 1
{
  "certificates": [
    {
      "raw": "MIIH...",
      "version": 3,
      "serial": "0",
      "sig_alg": "SHA1-RSA",
      "issuer": "CN=GLOBALTRUST,OU=GLOBALTRUST Certification Service,O=ARGE DATEN - Austrian Society for Data Protection,L=Vienna,ST=Austria,C=AT,1.2.840.113549.1.9.1=#0c15696e666f40676c6f62616c74727573742e696e666f",
      "not_before": "2006-08-07T14:12:35Z",
      "not_after": "2036-09-18T14:12:35Z",
      "subject": "CN=GLOBALTRUST,OU=GLOBALTRUST Certification Service,O=ARGE DATEN - Austrian Society for Data Protection,L=Vienna,ST=Austria,C=AT,1.2.840.113549.1.9.1=#0c15696e666f40676c6f62616c74727573742e696e666f",
      "pubkey_alg": "RSA",
      "ski": "c001d5e0781f2f743ae3ebc02152a604ee26cba4",
      "aki": "c001d5e0781f2f743ae3ebc02152a604ee26cba4",
      "policies": [
        "2.5.29.32.0"
      ],
      "key_usage": [
        "digitalSignature(00000001)",
        "contentCommitment(00000010)",
        "keyCertSign(00100000)",
        "cRLSign(01000000)"
      ]
    },
...
```

Some root certificates fail RFC 5280 compliance check and would result in errors as shown below.
These kind of error messages are output to standard error.

```sh
time=2026-05-29T18:29:55.677+09:00 level=WARN msg="failed to parse root certificate, skipped" location=147 err="x509: negative serial number" cert="MIIFVjCCBD6..."
time=2026-05-29T18:29:55.688+09:00 level=WARN msg="failed to parse root certificate, skipped" location=653 err="x509: invalid RDNSequence: invalid attribute value: unsupported string type: 3" cert="MIIFxDCCBKygA..."
```

### `add-chain`

Before submitting, confirm the certificate's `NotAfter` falls within the log's temporal shard:

```sh
sct logs --state usable --interval
```

And confirm the chain is accepted by the log's root certificates:

```sh
sct get-roots --log 31
```

Then submit:

```sh
# Submit a certificate and its chain from local PEM files to log 26
sct add-chain --log 26 --pem ./leaf.pem --chain ./chain.pem

# Fetch the certificate from a URL and submit to log 31
sct add-chain --log 31 --url https://example.com
```

Below are example outputs.

```sh
# Add to RFC 6962 log
$ sct add-chain --log 26 --url https://example.com
{
  "added_at": "2026-05-29T08:51:38.923482839Z",
  "log": {
    "id": 26,
    "operator": "Sectigo",
    "description": "Sectigo 'Tiger2026h2'",
    "log_id": "yKPEf8ezrbk1awE/anoSbeM6TkOlxkb5l605dZkdz5o=",
    "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfJFUD/FRkonvZIA9ZT1J3yvA4EpSp3innbIVpMTDR1oCe5vguapheQ7wYiWaCES1EL1B+2BEC+P5bUfwF44lnA==",
    "state": "usable",
    "api_type": "rfc6962",
    "start_inclusive": "2026-07-01T00:00:00Z",
    "end_exclusive": "2027-01-01T00:00:00Z",
    "url": "https://tiger2026h2.ct.sectigo.com/"
  },
  "response": {
    "sct_version": 0,
    "id": "yKPEf8ezrbk1awE/anoSbeM6TkOlxkb5l605dZkdz5o=",
    "timestamp": "2026-04-02T22:14:37.455Z",
    "signature": "BAMARzBFAiEAxSnCae8DA1boj9IqqRpoLZGC54qHOHXniBlrGqZg/V4CIFjWlY0cMIVBeEjq+spF6diMz46v7fEdIEX/q6vc2fcx"
  }
}
```

```sh
# Add to Static CT API log
# Note that "leaf_index" value under response.extensions is returned only when using Static CT API log
$ sct add-chain --log 45 --url https://example.com
{
  "added_at": "2026-05-29T09:40:14.671787258Z",
  "log": {
    "id": 45,
    "operator": "Geomys",
    "description": "Geomys 'Tuscolo2026h2'",
    "log_id": "Rq+GPTs+5Z+ld96oJF02sNntIqIj9GF3QSKUUu6VUF8=",
    "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaA6P0i7JTsd9XfzF1/76avRWA3XXI4NStsFO/aFtBp6SY7olDEMiPSFSxGzFQjKA1r9vgG/oFQwurlWMy9FQNw==",
    "state": "usable",
    "api_type": "static",
    "start_inclusive": "2026-07-01T00:00:00Z",
    "end_exclusive": "2027-01-01T00:00:00Z",
    "key_id": "ec18922f",
    "origin": "tuscolo2026h2.sunlight.geomys.org",
    "monitoring_url": "https://tuscolo2026h2.skylight.geomys.org/",
    "submission_url": "https://tuscolo2026h2.sunlight.geomys.org/"
  },
  "response": {
    "sct_version": 0,
    "id": "Rq+GPTs+5Z+ld96oJF02sNntIqIj9GF3QSKUUu6VUF8=",
    "timestamp": "2026-05-27T09:13:28.529Z",
    "extensions": {
      "extension_type": 0,
      "extension_length": 5,
      "extension_value": 130438194
    },
    "signature": "BAMASDBGAiEA07wV+o3IjMLoED6CmCbIFGu/fnmAO9yF0Xieke5+oOcCIQDtNmFD415X+kknXkVH5TtFRMfGYmV0PFmENAunj3/HKg=="
  }
}
```

```sh
# add-chain fails if the certificate's NotAfter does not match the log's temporal sharding interval
$ sct logs --type static --interval | grep 44
44  static    Geomys 'Tuscolo2026h1'           usable  2026-01-01T00:00:00Z  2026-07-01T00:00:00Z

$ sct add-chain --log 44 --url https://example.com
failed to add, the certificate's NotAfter does not match the log's temporal shard: NotAfter=2026-07-01T21:24:46Z, shard=[2026-01-01T00:00:00Z,2026-07-01T00:00:00Z)
```
