#!/usr/bin/env python3
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Test HIP program that runs inside an AXIS sandbox.
Uses the hip-remote client library to talk to a remote hip-worker.
Verifies: device discovery, memory alloc/free, memcpy round-trip.
"""
import ctypes
import ctypes.util
import os
import sys

def main():
    # Load the hip-remote client library
    lib_path = os.environ.get("HIP_REMOTE_LIB", "libamdhip64.so")
    try:
        hip = ctypes.CDLL(lib_path)
    except OSError as e:
        print(f"FAIL: cannot load {lib_path}: {e}")
        return 1

    print(f"Loaded: {lib_path}")
    print(f"Worker: {os.environ.get('TF_WORKER_HOST', '?')}:{os.environ.get('TF_WORKER_PORT', '?')}")
    print()

    results = []

    # ── Test 1: hipGetDeviceCount ──
    count = ctypes.c_int(0)
    ret = hip.hipGetDeviceCount(ctypes.byref(count))
    if ret == 0 and count.value > 0:
        print(f"PASS: hipGetDeviceCount = {count.value} device(s)")
        results.append(True)
    else:
        print(f"FAIL: hipGetDeviceCount returned {ret}, count={count.value}")
        results.append(False)
        if count.value == 0:
            print("  No GPU visible — hip-worker may not have a GPU")
            return 1

    # ── Test 2: hipSetDevice ──
    ret = hip.hipSetDevice(0)
    if ret == 0:
        print("PASS: hipSetDevice(0)")
        results.append(True)
    else:
        print(f"FAIL: hipSetDevice(0) returned {ret}")
        results.append(False)
        return 1

    # ── Test 3: hipGetDeviceProperties ──
    # hipDeviceProp_t is a large struct (~800 bytes). We'll just read the name.
    prop_buf = ctypes.create_string_buffer(1024)
    ret = hip.hipGetDeviceProperties(prop_buf, 0)
    if ret == 0:
        # Name is the first 256 bytes of hipDeviceProp_t
        name = prop_buf.raw[:256].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f"PASS: hipGetDeviceProperties — name='{name}'")
        results.append(True)
    else:
        print(f"FAIL: hipGetDeviceProperties returned {ret}")
        results.append(False)

    # ── Test 4: hipMalloc + hipFree ──
    dev_ptr = ctypes.c_void_p(0)
    size = 1024 * 1024  # 1MB
    ret = hip.hipMalloc(ctypes.byref(dev_ptr), ctypes.c_size_t(size))
    if ret == 0 and dev_ptr.value:
        print(f"PASS: hipMalloc(1MB) — ptr=0x{dev_ptr.value:x}")
        results.append(True)

        # ── Test 5: hipMemcpy H2D + D2H round-trip ──
        # Write a pattern to host buffer, copy to device, copy back, verify
        host_src = (ctypes.c_char * 256)(*[ctypes.c_char(i & 0xFF) for i in range(256)])
        host_dst = (ctypes.c_char * 256)()

        # hipMemcpyHostToDevice = 1, hipMemcpyDeviceToHost = 2
        ret1 = hip.hipMemcpy(dev_ptr, host_src, ctypes.c_size_t(256), 1)
        ret2 = hip.hipMemcpy(host_dst, dev_ptr, ctypes.c_size_t(256), 2)

        if ret1 == 0 and ret2 == 0:
            match = all(host_dst[i] == host_src[i] for i in range(256))
            if match:
                print("PASS: hipMemcpy H2D + D2H round-trip — data verified")
                results.append(True)
            else:
                print("FAIL: hipMemcpy data mismatch")
                results.append(False)
        else:
            print(f"FAIL: hipMemcpy H2D={ret1} D2H={ret2}")
            results.append(False)

        # Free
        ret = hip.hipFree(dev_ptr)
        if ret == 0:
            print("PASS: hipFree")
            results.append(True)
        else:
            print(f"FAIL: hipFree returned {ret}")
            results.append(False)
    else:
        print(f"FAIL: hipMalloc returned {ret}")
        results.append(False)

    # ── Test 6: hipDeviceSynchronize ──
    ret = hip.hipDeviceSynchronize()
    if ret == 0:
        print("PASS: hipDeviceSynchronize")
        results.append(True)
    else:
        print(f"FAIL: hipDeviceSynchronize returned {ret}")
        results.append(False)

    # ── Summary ──
    passed = sum(results)
    total = len(results)
    print(f"\n{'='*50}")
    print(f"Result: {passed}/{total} HIP tests passed")
    if passed == total:
        print("All HIP API calls work through hip-remote proxy!")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
