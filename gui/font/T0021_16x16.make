T=0021
D=2121
a=14
d=2
1| zcat ~/fonts/jis/izmg16-2004-1.bdf.gz | bdftoscobf # JIS X 0213 plane 1
2| zcat ~/fonts/jis/izmg16-2004-2.bdf.gz | bdftoscobf # JIS X 0213 plane 2
3| zcat ~/fonts/jis/jisksp16-1990.bdf.Z | bdftoscobf # JIS X 0212
4| zcat /usr/share/fonts/X11/misc/gb16fs.pcf.gz | pcf2bdf | bdftoscobf # GB 2312
5| zcat /usr/share/fonts/X11/misc/hanglg16.pcf.gz | pcf2bdf | bdftoscobf # KS C 5601
N+140
*

:JIS X 0213:2004 plane 1 -- public domain; by Yu Izumi, 2001-2007
;
1

:JIS X 0213:2004 plane 2 -- public domain; by Yu Izumi, 2001-2007
T 21=87,23=88*3,28=8B,2C=8C*4,6E=90*11
; @HT$LY
2

:JIS X 0212 -- Version 0.981 (July 17, 1998)
; 8000+
3

:GB 2312:1980 -- Copyright (c) 1988 The Institute of Software, Academia Sinica.
; 2121- @H 5E* @L+ $. @7E/$7E%Y 2180+
4

:KS C 5601 -- Copyright (c) 1987, 1988 Daewoo Electronics Co.,Ltd.
; 2121- @H 5E* @L+ $. @7E/$7E%Y B780+
5

:6-dot Braille -- public domain
; #40/(Z) 8021+
M
................
................
................
....aa....dd....
....aa....dd....
................
................
....bb....ee....
....bb....ee....
................
................
....cc....ff....
....cc....ff....
................
................
................

:8-dot Braille -- public domain
T:=8121*5E=8221*5E=8321*5E
; T
M
................
....aa....ee....
....aa....ee....
................
................
....bb....ff....
....bb....ff....
................
................
....cc....gg....
....cc....gg....
................
................
....dd....hh....
....dd....hh....
................

*