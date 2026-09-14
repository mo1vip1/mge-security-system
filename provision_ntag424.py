#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MGE Security - NTAG 424 DNA Provisioning Tool"""
import sys
from smartcard.System import readers


def provision():
    available_readers = readers()
    if not available_readers:
        print("لم يتم العثور على قارئ NFC")
        sys.exit(1)
    connection = available_readers[0].createConnection()
    connection.connect()
    connection.transmit([0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00])
    print("تم تهيئة الشريحة بنجاح.")


if __name__ == "__main__":
    provision()
