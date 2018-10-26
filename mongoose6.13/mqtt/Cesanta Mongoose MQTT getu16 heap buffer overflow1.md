# Cesanta Mongoose MQTT getu16 Heap Buffer Qverflow

## Summary

* An exploitable arbitrary memory read vulnerability exists in the MQTT packet parsing functionality of Cesanta Mongoose 6.13. A specially crafted MQTT SUBSCRIBE packet can cause an arbitrary out-of=bounds memory read potentially resulting in information disclosure and denial of service. An attacker needs to send a specially crafted MQTT packet over the network to trigger this vulnerability.

## Tested Versions

* Cesanta Mongoose 6.13

## Details

Mongoose is a monolithic library implementing a number of networking protocols, including HTTP, MQTT, MDNS and others. It is designed with embedded devices in mind and as such is used in many IoT devices and runs on virtually all platforms.

While parsing an MQTT packet SUBSCRIBE command in file `mg_mqtt.c`, `*p` is defined to accpet the value from `mbuf *io` without any additional validation. After that, function `getu16` is called when decode mqtt variable length. This arbitrary length value is used in pointer arithmetic and can cause out-of-bounds memory access. The vulnerability occurs in function `parse_mqtt`:


```C++
static uint16_t getu16(const char *p) {
  const uint8_t *up = (const uint8_t *) p;
  return (up[0] << 8) + up[1];
}
```

## Crash Information

* This vulnerability can be triggered by sending bytes from the [proof of concept](./getu16-1.crash) to the sample mqtt_broker application supplied with the library.

```
==5025==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000051 at pc 0x000000574250 bp 0x7fffffffc2f0 sp 0x7fffffffc2e8
READ of size 1 at 0x603000000051 thread T0
    #0 0x57424f  (mqtt_broker+0x57424f)
    #1 0x5740aa  (mqtt_broker+0x5740aa)
    #2 0x573142  (mqtt_broker+0x573142)
    #3 0x562079  (mqtt_broker+0x562079)
    #4 0x540d65  (mqtt_broker+0x540d65)
    #5 0x57202f  (mqtt_broker+0x57202f)
    #6 0x545683  (mqtt_broker+0x545683)
    #7 0x54506e  (mqtt_broker+0x54506e)
    #8 0x55249b  (mqtt_broker+0x55249b)
    #9 0x55706e  (mqtt_broker+0x55706e)
    #10 0x543373  (mqtt_broker+0x543373)
    #11 0x516af6  (mqtt_broker+0x516af6)
    #12 0x7ffff6ee582f  (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #13 0x41ac88  (mqtt_broker+0x41ac88)

0x603000000051 is located 0 bytes to the right of 17-byte region [0x603000000040,0x603000000051)
allocated by thread T0 here:
    #0 0x4df320  (mqtt_broker+0x4df320)
    #1 0x53201d  (mqtt_broker+0x53201d)
    #2 0x532376  (mqtt_broker+0x532376)
    #3 0x571fcb  (mqtt_broker+0x571fcb)
    #4 0x545683  (mqtt_broker+0x545683)
    #5 0x54506e  (mqtt_broker+0x54506e)
    #6 0x55249b  (mqtt_broker+0x55249b)
    #7 0x55706e  (mqtt_broker+0x55706e)
    #8 0x543373  (mqtt_broker+0x543373)
    #9 0x516af6  (mqtt_broker+0x516af6)
    #10 0x7ffff6ee582f  (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)

SUMMARY: AddressSanitizer: heap-buffer-overflow (mqtt_broker+0x57424f)
Shadow bytes around the buggy address:
  0x0c067fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c067fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c067fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c067fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c067fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c067fff8000: fa fa 00 00 00 fa fa fa 00 00[01]fa fa fa fa fa
  0x0c067fff8010: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==5025==ABORTING
[Inferior 1 (process 5025) exited with code 01]
```
