# Cesanta Mongoose MQTT mg_mqtt_next_subscribe_topic Heap Buffer Overflow

## Summary

* An exploitable arbitrary memory read vulnerability exists in the MQTT packet parsing functionality of Cesanta Mongoose 6.13. A specially crafted MQTT SUBSCRIBE packet can cause an arbitrary out-of=bounds memory read potentially resulting in information disclosure and denial of service. An attacker needs to send a specially crafted MQTT packet over the network to trigger this vulnerability.

## Tested Versions

* Cesanta Mongoose 6.13

## Details

Mongoose is a monolithic library implementing a number of networking protocols, including HTTP, MQTT, MDNS and others. It is designed with embedded devices in mind and as such is used in many IoT devices and runs on virtually all platforms.

While parsing an MQTT packet SUBSCRIBE command, topic string size as encoded in the packet is trusted without any additional validation. This arbitrary length value is used in pointer arithmetic and can cause out-of-bounds memory access. The vulnerability occurs in function `mg_mqtt_next_subscribe_topic`:

```C++
int mg_mqtt_next_subscribe_topic(struct mg_mqtt_message *msg,
                                 struct mg_str *topic, uint8_t *qos, int pos) {
  unsigned char *buf = (unsigned char *) msg->payload.p + pos;
  int new_pos;

  if ((size_t) pos >= msg->payload.len) return -1;

  topic->len = buf[0] << 8 | buf[1];                     [1]
  topic->p = (char *) buf + 2;
  new_pos = pos + 2 + topic->len + 1;                    [2]
  if ((size_t) new_pos > msg->payload.len) return -1;
  *qos = buf[2 + topic->len];
  return new_pos;
}
```

* In the above code, at [1] two bytes from message buffer are read as `topic->len` and then immediatelly used at [2] to calculate `new_pos`. No check is performed to insure it would be inside the bounds of the buffer which is limited in size. This issue can be triggered multiple times and with careful control of the memory layout could be abused to leak memory and cause denial of service.

* This vulnerability can be triggered by sending bytes from the [proof of concept](./mg_mqtt_next_subscribe_topic.crash) to the sample mqtt_broker application supplied with the library.

## Crash Information

```
==5469==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000da at pc 0x000000564f4c bp 0x7fffffffc070 sp 0x7fffffffc068
READ of size 1 at 0x6020000000da thread T0
    #0 0x564f4b  (mqtt_broker+0x564f4b)
    #1 0x566cac  (mqtt_broker+0x566cac)
    #2 0x5665e7  (mqtt_broker+0x5665e7)
    #3 0x516bc3  (mqtt_broker+0x516bc3)
    #4 0x56274a  (mqtt_broker+0x56274a)
    #5 0x540d65  (mqtt_broker+0x540d65)
    #6 0x57202f  (mqtt_broker+0x57202f)
    #7 0x545683  (mqtt_broker+0x545683)
    #8 0x54506e  (mqtt_broker+0x54506e)
    #9 0x55249b  (mqtt_broker+0x55249b)
    #10 0x55706e  (mqtt_broker+0x55706e)
    #11 0x543373  (mqtt_broker+0x543373)
    #12 0x516af6  (mqtt_broker+0x516af6)
    #13 0x7ffff6ee582f  (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #14 0x41ac88  (mqtt_broker+0x41ac88)

0x6020000000da is located 0 bytes to the right of 10-byte region [0x6020000000d0,0x6020000000da)
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

SUMMARY: AddressSanitizer: heap-buffer-overflow (mqtt_broker+0x564f4b)
Shadow bytes around the buggy address:
  0x0c047fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff8000: fa fa 00 fa fa fa 00 00 fa fa 00 00 fa fa fd fd
=>0x0c047fff8010: fa fa fd fa fa fa fd fa fa fa 00[02]fa fa fa fa
  0x0c047fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8060: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==5469==ABORTING
[Inferior 1 (process 5469) exited with code 01]
```
