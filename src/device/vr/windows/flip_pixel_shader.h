// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// DO NOT MODIFY.  Use generate_shaders.bat to modify, then re-add this warning.
#ifndef DEVICE_VR_WINDOWS_FLIP_PIXEL_SHADER_H_
#define DEVICE_VR_WINDOWS_FLIP_PIXEL_SHADER_H_

#if 0
//
// Generated by Microsoft (R) HLSL Shader Compiler 6.3.9600.16384
//
//
// Resource Bindings:
//
// Name                                 Type  Format         Dim Slot Elements
// ------------------------------ ---------- ------- ----------- ---- --------
// my_sampler                        sampler      NA          NA    0        1
// my_texture                        texture  float4          2d    0        1
//
//
//
// Input signature:
//
// Name                 Index   Mask Register SysValue  Format   Used
// -------------------- ----- ------ -------- -------- ------- ------
// SV_POSITION              0   xyzw        0      POS   float
// TEXCOORD                 0   xy          1     NONE   float   xy
//
//
// Output signature:
//
// Name                 Index   Mask Register SysValue  Format   Used
// -------------------- ----- ------ -------- -------- ------- ------
// SV_TARGET                0   xyzw        0   TARGET   float   xyzw
//
//
// Sampler/Resource to DX9 shader sampler mappings:
//
// Target Sampler Source Sampler  Source Resource
// -------------- --------------- ----------------
// s0             s0              t0               
//
//
// Level9 shader bytecode:
//
    ps_2_x
    dcl t0.xy
    dcl_2d s0
    texld r0, t0, s0
    mov oC0, r0

// approximately 2 instruction slots used (1 texture, 1 arithmetic)
ps_4_0
dcl_sampler s0, mode_default
dcl_resource_texture2d (float,float,float,float) t0
dcl_input_ps linear v1.xy
dcl_output o0.xyzw
sample o0.xyzw, v1.xyxx, t0.xyzw, s0
ret 
// Approximately 2 instruction slots used
#endif

const BYTE g_flip_pixel[] = {
    68,  88,  66,  67,  192, 36,  143, 138, 147, 91,  77,  61,  65,  22,  238,
    11,  132, 7,   50,  248, 1,   0,   0,   0,   196, 2,   0,   0,   6,   0,
    0,   0,   56,  0,   0,   0,   164, 0,   0,   0,   16,  1,   0,   0,   140,
    1,   0,   0,   56,  2,   0,   0,   144, 2,   0,   0,   65,  111, 110, 57,
    100, 0,   0,   0,   100, 0,   0,   0,   0,   2,   255, 255, 60,  0,   0,
    0,   40,  0,   0,   0,   0,   0,   40,  0,   0,   0,   40,  0,   0,   0,
    40,  0,   1,   0,   36,  0,   0,   0,   40,  0,   0,   0,   0,   0,   1,
    2,   255, 255, 31,  0,   0,   2,   0,   0,   0,   128, 0,   0,   3,   176,
    31,  0,   0,   2,   0,   0,   0,   144, 0,   8,   15,  160, 66,  0,   0,
    3,   0,   0,   15,  128, 0,   0,   228, 176, 0,   8,   228, 160, 1,   0,
    0,   2,   0,   8,   15,  128, 0,   0,   228, 128, 255, 255, 0,   0,   83,
    72,  68,  82,  100, 0,   0,   0,   64,  0,   0,   0,   25,  0,   0,   0,
    90,  0,   0,   3,   0,   96,  16,  0,   0,   0,   0,   0,   88,  24,  0,
    4,   0,   112, 16,  0,   0,   0,   0,   0,   85,  85,  0,   0,   98,  16,
    0,   3,   50,  16,  16,  0,   1,   0,   0,   0,   101, 0,   0,   3,   242,
    32,  16,  0,   0,   0,   0,   0,   69,  0,   0,   9,   242, 32,  16,  0,
    0,   0,   0,   0,   70,  16,  16,  0,   1,   0,   0,   0,   70,  126, 16,
    0,   0,   0,   0,   0,   0,   96,  16,  0,   0,   0,   0,   0,   62,  0,
    0,   1,   83,  84,  65,  84,  116, 0,   0,   0,   2,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   2,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   1,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   1,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   82,  68,  69,  70,  164, 0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   2,   0,   0,   0,   28,  0,   0,   0,
    0,   4,   255, 255, 0,   1,   0,   0,   114, 0,   0,   0,   92,  0,   0,
    0,   3,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   1,   0,   0,   0,   0,   0,   0,   0,   103,
    0,   0,   0,   2,   0,   0,   0,   5,   0,   0,   0,   4,   0,   0,   0,
    255, 255, 255, 255, 0,   0,   0,   0,   1,   0,   0,   0,   12,  0,   0,
    0,   109, 121, 95,  115, 97,  109, 112, 108, 101, 114, 0,   109, 121, 95,
    116, 101, 120, 116, 117, 114, 101, 0,   77,  105, 99,  114, 111, 115, 111,
    102, 116, 32,  40,  82,  41,  32,  72,  76,  83,  76,  32,  83,  104, 97,
    100, 101, 114, 32,  67,  111, 109, 112, 105, 108, 101, 114, 32,  54,  46,
    51,  46,  57,  54,  48,  48,  46,  49,  54,  51,  56,  52,  0,   73,  83,
    71,  78,  80,  0,   0,   0,   2,   0,   0,   0,   8,   0,   0,   0,   56,
    0,   0,   0,   0,   0,   0,   0,   1,   0,   0,   0,   3,   0,   0,   0,
    0,   0,   0,   0,   15,  0,   0,   0,   68,  0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   3,   0,   0,   0,   1,   0,   0,   0,   3,   3,
    0,   0,   83,  86,  95,  80,  79,  83,  73,  84,  73,  79,  78,  0,   84,
    69,  88,  67,  79,  79,  82,  68,  0,   171, 171, 171, 79,  83,  71,  78,
    44,  0,   0,   0,   1,   0,   0,   0,   8,   0,   0,   0,   32,  0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   3,   0,   0,   0,   0,   0,
    0,   0,   15,  0,   0,   0,   83,  86,  95,  84,  65,  82,  71,  69,  84,
    0,   171, 171};

#endif  // DEVICE_VR_WINDOWS_FLIP_PIXEL_SHADER_H_
