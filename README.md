# Bitcoin signature generation and verification (proof of concept)

The 2 programs, `gensig` and `versig`, are capable of generating and verifying Bitcoin message signatures.

## How to install

```shell
$ pip3 install --user -r requirements.txt
```

## How to run

### gensig

The signature generator

```
$ gensig.py --help
usage: gensig.py [-h] [--verbose] [--bech32-hrp {bc,bcrt,df}] --message
                 MESSAGE

Given a message, generates a random address and the signature.

optional arguments:
  -h, --help            show this help message and exit
  --verbose             verbose processing
  --bech32-hrp {bc,bcrt,df}
                        Bech32 address type (human-readable prefix)
  --message MESSAGE     Message to sign (plain ASCII)

This program comes with ABSOLUTELY NO WARRANTY.
```

### versig

The signature verifier

```
$ versig.py --help
usage: versig.py [-h] [--verbose] --addr ADDR --message MESSAGE --sig SIG

Given an address, a message and a signature, extracts the public key and
verifies the signature.

optional arguments:
  -h, --help         show this help message and exit
  --verbose          verbose processing
  --addr ADDR        Bitcoin address
  --message MESSAGE  Message (plain ASCII)
  --sig SIG          signature (base64 encoded)

This program comes with ABSOLUTELY NO WARRANTY.
```

## Example

```
$ gensig.py --message "hi there!"
Public key : bc1q7qn5sprxl5xzg2r0aqgvkjwkaf4rtl58yp2adc
Message    : hi there!
Signature  : MEUCIH1+j9BPoo3k/YO6bDVSwBJTvAdaQSSExC4+hpksfGxpAiEA37aBoZa8+wi3Ns1dMeyqhi/IgT0Wx7wiIjBX+lvrkos=
```

```
$ versig.py --addr "bc1q7qn5sprxl5xzg2r0aqgvkjwkaf4rtl58yp2adc" --message "hi there!" --sig "MEUCIH1+j9BPoo3k/YO6bDVSwBJTvAdaQSSExC4+hpksfGxpAiEA37aBoZa8+wi3Ns1dMeyqhi/IgT0Wx7wiIjBX+lvrkos="
Signature verification OK!
```

```
$ versig.py --addr "bc1q7qn5sprxl5xzg2r0aqgvkjwkaf4rtl58yp2adc" --message "wrong message" --sig "MEUCIH1+j9BPoo3k/YO6bDVSwBJTvAdaQSSExC4+hpksfGxpAiEA37aBoZa8+wi3Ns1dMeyqhi/IgT0Wx7wiIjBX+lvrkos="
Signature verification error.
```

## Example files

### Example 1

```
Address   : bc1qshk9l4fqzukgmpj2dsp7r33v2768ugm032g847
Message   : hi
Signature : Hww2Wa22bdvT+zzxrhatUwkDL/lfB7Ta+h5YR+ny2wIsIdzNgkTIkQSbrx0HKJ49PyR2In91N6tW8YoRIuPyT0Y=
```

This one works with https://www.verifybitcoinmessage.com/ .

Signature contents:

```shell
$ echo "Hww2Wa22bdvT+zzxrhatUwkDL/lfB7Ta+h5YR+ny2wIsIdzNgkTIkQSbrx0HKJ49PyR2In91N6tW8YoRIuPyT0Y=" | base64 -d | hexdump -C 
00000000  1f 0c 36 59 ad b6 6d db  d3 fb 3c f1 ae 16 ad 53  |..6Y..m...<....S|
00000010  09 03 2f f9 5f 07 b4 da  fa 1e 58 47 e9 f2 db 02  |../._.....XG....|
00000020  2c 21 dc cd 82 44 c8 91  04 9b af 1d 07 28 9e 3d  |,!...D.......(.=|
00000030  3f 24 76 22 7f 75 37 ab  56 f1 8a 11 22 e3 f2 4f  |?$v".u7.V..."..O|
00000040  46                                                |F|
00000041
```

What type of signature is this?

### Example 2

```
Address   : bcrt1qgem02qkk5779rdg7gm6cq65pqagg73s6myww46
Message   : this_is_my_test_message
Signature : MEQCICN1zKUrGwgiWUyGLT1+cFxzjcALfoGN/buXYIVNg21bAiAC7LFXXn8zJkJCwH5kDiZ5h7wRUL4Eyj1J+oO79DgErQ==
```

This one appears to be a valid ECDSA signature:

```shell
$ echo "MEQCICN1zKUrGwgiWUyGLT1+cFxzjcALfoGN/buXYIVNg21bAiAC7LFXXn8zJkJCwH5kDiZ5h7wRUL4Eyj1J+oO79DgErQ==" | base64 -d | hexdump -C 
00000000  30 44 02 20 23 75 cc a5  2b 1b 08 22 59 4c 86 2d  |0D. #u..+.."YL.-|
00000010  3d 7e 70 5c 73 8d c0 0b  7e 81 8d fd bb 97 60 85  |=~p\s...~.....`.|
00000020  4d 83 6d 5b 02 20 02 ec  b1 57 5e 7f 33 26 42 42  |M.m[. ...W^.3&BB|
00000030  c0 7e 64 0e 26 79 87 bc  11 50 be 04 ca 3d 49 fa  |.~d.&y...P...=I.|
00000040  83 bb f4 38 04 ad                                 |...8..|
```

### Example 3

```
Adresse  : df1qk87jwkfsg4ayehzmf3rpxq2gytrx8eyqvrsr7m
Text     : this_is_my_test_message
Signatur : MEQCIEUL+7bCTXYZZkEN3kXEBEwwbU3f3Qcdvx3BKrSTA1d2AiBqwGcadqyKAI9UT2OpikPuBPlIvBJN7gi/0oDfBUbNWQ==
```

This one appears to be a valid ECDSA signature:

```shell
$ echo "MEQCIEUL+7bCTXYZZkEN3kXEBEwwbU3f3Qcdvx3BKrSTA1d2AiBqwGcadqyKAI9UT2OpikPuBPlIvBJN7gi/0oDfBUbNWQ==" | base64 -d | hexdump -C 
00000000  30 44 02 20 45 0b fb b6  c2 4d 76 19 66 41 0d de  |0D. E....Mv.fA..|
00000010  45 c4 04 4c 30 6d 4d df  dd 07 1d bf 1d c1 2a b4  |E..L0mM.......*.|
00000020  93 03 57 76 02 20 6a c0  67 1a 76 ac 8a 00 8f 54  |..Wv. j.g.v....T|
00000030  4f 63 a9 8a 43 ee 04 f9  48 bc 12 4d ee 08 bf d2  |Oc..C...H..M....|
00000040  80 df 05 46 cd 59                                 |...F.Y|
00000046
```

