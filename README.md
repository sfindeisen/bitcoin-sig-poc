# Bitcoin signature verification (proof of concept)

## Example 1

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

## Example 2

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

ECDSA signature format is summarized here:

1. https://bitcoin.stackexchange.com/a/12556
2. https://bitcoin.stackexchange.com/a/58859
3. https://bitcoin.stackexchange.com/a/92683

