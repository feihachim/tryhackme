# Crack the hash

![logo](./images/crack-the-hash-logo.jpeg)

## Description

Cracking hashes challenges

## Prérequis

### Outils utilisés

#### `haiti-hash`

pour identifier les hashes

#### `johntheripper` et `hashcat`

 pour effectuer les hashes

#### wordlist `rockyou.txt`

célèbre wordlist

### Installation

#### `johntheripper` et `hashcat` procédure d'installation

sont installés par défaut sur kali-linux

#### `haiti-hash` procédure d'installation

`sudo gem install haiti-hash`

```bash
[sudo] Mot de passe de $USER : 
Fetching haiti-hash-4.0.0.gem
Fetching paint-2.3.0.gem
Fetching docopt-0.6.1.gem
Successfully installed paint-2.3.0
Successfully installed docopt-0.6.1
Successfully installed haiti-hash-4.0.0
Parsing documentation for paint-2.3.0
Installing ri documentation for paint-2.3.0
Parsing documentation for docopt-0.6.1
Installing ri documentation for docopt-0.6.1
Parsing documentation for haiti-hash-4.0.0
Installing ri documentation for haiti-hash-4.0.0
Done installing documentation for paint, docopt, haiti-hash after 0 seconds
3 gems installed
```

#### wordlist `rockyou.txt` procédure d'installation

dans kali-linux,cette wordlist est compressé au format gz donc on l'extrait de l'archive avec la commande suivante:

`sudo gzip -d /usr/share/wordlists/rockyou.txt.gz`

## Tasks

### Task 1

#### Identification du hash 1

- commande:
`cat hash1.txt | haiti -`

- résultat:

```bash
MD5 [HC: 0] [JtR: raw-md5]
LM [HC: 3000] [JtR: lm]
NTLM [HC: 1000] [JtR: nt]
Domain Cached Credentials (DCC), MS Cache [HC: 1100] [JtR: mscash]
Domain Cached Credentials 2 (DCC2), MS Cache 2 [HC: 2100] [JtR: mscash2]
IPB 2.x (Invision Power Board) [HC: 2811]
WPA-EAPOL-PMK [HC: 2501]
WPA-EAPOL-PBKDF2 [HC: 2500]
Bitcoin WIF private key (P2PKH), uncompressed [HC: 28502]
Bitcoin WIF private key (P2PKH), compressed [HC: 28501]
Umbraco HMAC-SHA1 [HC: 24800]
RAdmin v2.x [HC: 9900] [JtR: radmin]
DNSSEC (NSEC3) [HC: 8300]
IPMI 2.0 RAKP HMAC-MD5 [HC: 7350]
Snefru-128 [JtR: snefru-128]
RIPEMD-128 [JtR: ripemd-128]
Keyed MD5: RIPv2, OSPF, BGP, SNMPv2 [JtR: net-md5]
Skype [HC: 23]
Lotus Notes/Domino 5 [HC: 8600] [JtR: lotus5]
Haval-128 (4 rounds) [JtR: haval-128-4]
MD4 [HC: 900] [JtR: raw-md4]
MD2 [JtR: md2]
```

- Le hash est probablement au format `MD5`

#### crackage du hash

- commande:

`john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt`

- resultat:

```bash
Created directory: /home/hachim/.john
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
easy             (?)     
1g 0:00:00:00 DONE (2026-01-18 01:35) 33.33g/s 5747Kp/s 5747Kc/s 5747KC/s florida69..eagames
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

- Mot de passe: `easy`

#### Identification du hash 2

```bash
cat hash2.txt | haiti - 

SHA-1 [HC: 100] [JtR: raw-sha1]
RIPEMD-160 [HC: 6000] [JtR: ripemd-160]
Double SHA-1 [HC: 4500]
Ruby on Rails Restful Auth (one round, no sitekey) [HC: 27200]
MySQL5.x [HC: 300] [JtR: mysql-sha1]
MySQL4.1 [HC: 300] [JtR: mysql-sha1]
Umbraco HMAC-SHA1 [HC: 24800]
WPA-EAPOL-PBKDF2 [HC: 2500]
WPA-EAPOL-PMK [HC: 2501]
Haval-160 (3 rounds) [JtR: dynamic_190]
Haval-160 (4 rounds) [JtR: dynamic_200]
Haval-160 (5 rounds) [JtR: dynamic_210]
HAS-160
LinkedIn [HC: 190] [JtR: raw-sha1-linkedin]
Skein-256(160)
Skein-512(160)
```

- Format: `SHA-1`

#### crackage du hash 2

```bash
john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt hash2.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (?)     
1g 0:00:00:00 DONE (2026-01-18 01:41) 20.00g/s 27680p/s 27680c/s 27680C/s jesse..password123
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed.
```

- Mot de passe: `password123`

#### Identification du hash 3

```bash
cat hash3.txt | haiti -

SHA-256 [HC: 1400] [JtR: raw-sha256]
GOST R 34.11-94 [HC: 6900] [JtR: gost]
SHA3-256 [HC: 17400] [JtR: dynamic_380]
Keccak-256 [HC: 17800] [JtR: raw-keccak-256]
Snefru-256 [JtR: snefru-256]
PANAMA [JtR: dynamic_320]
BLAKE2-256 (blake2b)
BLAKE2-256 (blake2s)
MD6-256 [HC: 34600]
sm3
Shake-128 (256)
Shake-256 (256)
Shake-512 (256)
BLAKE3
Streebog-256
IPMI 2.0 RAKP HMAC-SHA1 [HC: 7300]
Umbraco HMAC-SHA1 [HC: 24800]
WPA-EAPOL-PBKDF2 [HC: 2500]
WPA-EAPOL-PMK [HC: 2501]
RIPEMD-256 [JtR: dynamic_140]
Haval-256 (3 rounds) [JtR: haval-256-3]
Haval-256 (4 rounds) [JtR: dynamic_290]
Haval-256 (5 rounds) [JtR: dynamic_300]
GOST CryptoPro S-Box
Skein-256 [JtR: skein-256]

```

- Format: `SHA-256`

#### Crackage du hash 3

```bash
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash3.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (?)     
1g 0:00:00:00 DONE (2026-01-18 01:51) 50.00g/s 3276Kp/s 3276Kc/s 3276KC/s 123456..sabrina7
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 
```

- Mot de passe: `letmein`

#### Identification du hash 4

```bash
cat hash4.txt | haiti -

bcrypt [HC: 3200] [JtR: bcrypt]
Blowfish(OpenBSD) [HC: 3200] [JtR: bcrypt]
Woltlab Burning Board 4.x
bcrypt(sha256($pass)) / bcryptsha256 [HC: 30600]

```

- Format: `bcrypt`

#### Crackage du hash 4

- pour ce ces on doit d'abord filtrer la wordlist `rockyou.txt` en ne gardant que les mots de 4 caractères ou le programme va être très long.Pou ce faire,une méthode que j'ai utilisé est de construire une nouvelle wordlist nommée `rockyou_4chars.txt` avec la commande suivante:

`grep -x '.\{4\}' /usr/share/wordlists/rockyou.txt > rockyou_4chars.txt`

puis,on exécute la commande suivante

```bash
john --format=bcrypt --wordlist=rockyou_4chars.txt hash4.txt

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:08 2.77% (ETA: 02:18:06) 0g/s 56.25p/s 56.25c/s 56.25C/s 1229..todd
bleh             (?)     
1g 0:00:00:12 DONE (2026-01-18 02:13) 0.08257g/s 56.48p/s 56.48c/s 56.48C/s bleh..mets
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- Mot de passe: `bleh`

#### Identification et crackage du hash 5

sur le site [crackstation](https://crackstation.net/), on insère le hash dans le champ dde texte et il identifie le type de hash ainsi wue le mot de passe

![hash5](./images/hash5.png)

- Format: `MD4`

- Mot de passe: `Eternity22`
