Protocol
========
This document describes `snc`'s inner workings.


Algorithms
----------
### **AES** ###
For encryption, `snc` utilizes Rijndael, the AES (Advanced Encryption Standard). The code is a clone
of [my own AES implementation](https://github.com/hiatus/aes). The default key size is set to 256,
but it can be safely altered due to the usage of SHA3, which provides flexible digest length.

### **SHA3** ###
The SHA3 algorithm is used for key hashing as it allows for flexible digest length. Because of this,
the AES key size can be altered in `src/include/aes.h` without any further adjustments.

### **CRC32** ###
CRC32 is used for packet integrity checking.


Authentication
--------------
Authentication starts with the client to harden against service fingerprinting. If the first message
received from the client has unexpected size, the connection is simply closed. Effectively, `snc`'s
authentication works in a 3-way handshake and inherently provides mutual authentication.

0. Client generates 2 random 16-byte AES IVs and a random 16-byte challenge.
1. Client initializes two AES states with it's key and generated IVs. One for encryption and another
one for decryption.
2. Client encrypts the challenge.
3. Client concatenates IVs and challenge and sends the corresponding 48 bytes to the server.
4. Server receives IVs and challenge.
5. Server initializes two AES states with it's key and received IVs. One for decryption and another
one for encryption (the client's encryption state is the server's decryption state and vice-versa).
6. Server decrypts the challenge and stores the result.
7. Server encrypts the challenge.
8. Server sends the challenge to the client.
9. Client receives the challenge from the server.
10. Client decrypts the challenge and stores the result.
11. Client encrypts the challenge.
12. Client sends the challenge to the server.
13. Server receives the challenge.
14. Server decrypts the challenge.
15. Both sides now have the necessary information authenticate each other.


Data Transfer
-------------
Data transfer is a symmetrical process (same routine for both sides) and happens asynchronously. The
data polling loop continues until EOF is read on either side.

### **Data Packet** ###
Below is a snippet from `src/include/net.h` describing `snc`'s packet structure.

```c
// Make header size divisible by AES_SIZE_BLOCK
#define HDR_SIZE_PADDING 8

// Up to 32Kb per packet (also divisible by AES_SIZE_BLOCK)
#define PKT_SIZE_PAYLOAD 32768

// The snc header data
struct SNCHeader {
	uint32_t size;
	uint32_t crc32;
	uint8_t padding[HDR_SIZE_PADDING];
};

// The snc packet data
struct SNCPacket {
	struct SNCHeader hdr;
	uint8_t payload[PKT_SIZE_PAYLOAD];
};
```

### **Sender** ###
0. Read at most `PKT_SIZE_PAYLOAD` bytes from it's input into `snc_packet.payload`.
1. Pad `snc_packet.payload` with random bytes until it's size is divisible by `AES_SIZE_BLOCK`.
2. Set `snc_packet.snc_header.size` to the original data size.
3. Set `snc_packet.snc_header.crc32` to the CRC32 of the original data.
4. Encrypt `snc_packet.snc_header`.
5. Encrypt `snc_packet.payload`.
6. Send packet.

### **Receiver** ###
0. Read `sizeof(snc_header)` bytes from the socket into `snc_packet.snc_header`.
1. Decrypt `snc_packet.snc_header`.
2. Read `snc_packet.snc_header.size` bytes plus padding from the socket into `snc_packet.payload`.
3. Decrypt `snc_packet.payload`.
4. Verify the integrity of `snc_packet.payload` by checking it's CRC32 against `snc_header.crc32`.
5. If the integrity check fails, close the connection with the appropriate error.
