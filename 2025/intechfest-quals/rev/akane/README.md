---
title: Akane
categories: "Reverse Engineering"
authors: aimardcr
tags: 
draft: false
completedDuringEvent: true
submitted: true
points: 101
solves: 33
flags: INTECHFEST{}
---

> Note: Flag is in the environment variable.

---

The challenge ships a minimal HTTP server that mounts a static folder, serves a JSON greeting on `/`, enables logging, and most importantly installs a custom middleware that can reflect process startup strings back to the client when "debug" headers are present. Because on ELF/Linux the process startup area places the `envp` array immediately after the `argv` array in memory, indexing past `argv` lets us read environment variables. Since the flag lives in an environment variable, the "debug" middleware becomes an exfiltration primitive.

The `main` function constructs the server and wire-ups:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[240]; // [rsp+10h] [rbp-210h] BYREF
  _BYTE v5[47]; // [rsp+100h] [rbp-120h] BYREF
  char v6; // [rsp+12Fh] [rbp-F1h] BYREF
  _BYTE v7[47]; // [rsp+130h] [rbp-F0h] BYREF
  char v8; // [rsp+15Fh] [rbp-C1h] BYREF
  _BYTE v9[43]; // [rsp+160h] [rbp-C0h] BYREF
  char v10; // [rsp+18Bh] [rbp-95h] BYREF
  int v11; // [rsp+18Ch] [rbp-94h] BYREF
  _BYTE v12[40]; // [rsp+190h] [rbp-90h] BYREF
  const char **v13; // [rsp+1B8h] [rbp-68h] BYREF
  _BYTE v14[47]; // [rsp+1C0h] [rbp-60h] BYREF
  char v15; // [rsp+1EFh] [rbp-31h] BYREF
  char *v16; // [rsp+1F0h] [rbp-30h]
  char *v17; // [rsp+1F8h] [rbp-28h]
  char *v18; // [rsp+200h] [rbp-20h]

  akane::create_server((akane *)v4);
  akane::Server::set_thread_pool_size((akane::Server *)v4, 4u);
  v18 = &v6;
  std::string::basic_string<std::allocator<char>>(v5, "static", &v6);
  akane::Server::set_static_directory(v4, v5);
  std::string::~string(v5);
  std::function<akane::Response ()(akane::Context &)>::function<main::{lambda(akane::Context &)#1},void>(v7, &v8);
  v17 = &v10;
  std::string::basic_string<std::allocator<char>>(v9, "/", &v10);
  akane::Server::get(v4, v9, v7);
  std::string::~string(v9);
  std::function<akane::Response ()(akane::Context &)>::~function(v7);
  v11 = 1;
  akane::Server::use<akane::Logger,akane::Logger::Level>(v4, &v11);
  v13 = argv;
  std::function<bool ()(akane::Context &)>::function<main::{lambda(akane::Context &)#2},void>(v12, &v13);
  akane::Server::use(v4, v12);
  std::function<bool ()(akane::Context &)>::~function(v12);
  v16 = &v15;
  std::string::basic_string<std::allocator<char>>(v14, "0.0.0.0", &v15);
  akane::Server::bind(v4, v14, 5000);
  std::string::~string(v14);
  akane::Server::start((akane::Server *)v4);
  akane::Server::~Server((akane::Server *)v4);
  return 0;
}
```

The server is created, uses four worker threads, and serves files from `./static`. It registers a GET handler for `/` (the first lambda) and then pushes two middlewares: a logger and a custom "function middleware" constructed from the second lambda. Note the line `v13 = argv; ... function<...>(v12, &v13);` this passes a pointer to `argv` into the lambda’s closure, so the lambda can later access the process startup strings. The server binds on `0.0.0.0:5000` and starts.

How `get` attaches the route:

```c
__int64 __fastcall akane::Server::get(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  _BYTE v5[40]; // [rsp+20h] [rbp-30h] BYREF

  v3 = std::move<std::function<akane::Response ()(akane::Context &)> &>(a3);
  std::function<akane::Response ()(akane::Context &)>::function(v5, v3);
  akane::Router::get(a1, a2, v5);
  return std::function<akane::Response ()(akane::Context &)>::~function(v5);
}
```

This simply moves the route functor into the router under path `a2` (the string `"/"`).

The `/` handler (lambda #1) response:

```c
__int64 __fastcall main::{lambda(akane::Context &)#1}::operator()(__int64 a1)
{
  __int64 v1; // r9
  _BYTE *i; // rbx
  __int64 *j; // rbx
  _BYTE *k; // rbx
  _BYTE v6[16]; // [rsp+50h] [rbp-D0h] BYREF
  _BYTE v7[24]; // [rsp+60h] [rbp-C0h] BYREF
  __int64 v8; // [rsp+78h] [rbp-A8h] BYREF
  _BYTE v9[24]; // [rsp+90h] [rbp-90h] BYREF
  __int64 v10; // [rsp+A8h] [rbp-78h] BYREF
  _BYTE v11[24]; // [rsp+C0h] [rbp-60h] BYREF
  __int64 v12; // [rsp+D8h] [rbp-48h] BYREF
  __int64 v13; // [rsp+F0h] [rbp-30h] BYREF

  nlohmann::json_abi_v3_11_3::detail::json_ref<nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>>::json_ref<char const(&)[8],0>(
    v9,
    "message");
  nlohmann::json_abi_v3_11_3::detail::json_ref<nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>>::json_ref<char const(&)[30],0>(
    &v10,
    "Welcome to Akane HTTP Server!");
  nlohmann::json_abi_v3_11_3::detail::json_ref<nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>>::json_ref(
    v7,
    v9,
    2);
  nlohmann::json_abi_v3_11_3::detail::json_ref<nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>>::json_ref<char const(&)[8],0>(
    v11,
    "version");
  nlohmann::json_abi_v3_11_3::detail::json_ref<nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>>::json_ref<char const(&)[6],0>(
    &v12,
    "1.0.0");
  nlohmann::json_abi_v3_11_3::detail::json_ref<nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>>::json_ref(
    &v8,
    v11,
    2);
  nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>::basic_json(
    v6,
    v7,
    2,
    1,
    2,
    v1,
    v7,
    2);
  akane::Response::Response(a1, v6);
  nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>::~basic_json(v6);
  for ( i = v9;
        i != v7;
        nlohmann::json_abi_v3_11_3::detail::json_ref<nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>>::~json_ref(i) )
  {
    i -= 24;
  }
  for ( j = &v13;
        j != (__int64 *)v11;
        nlohmann::json_abi_v3_11_3::detail::json_ref<nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>>::~json_ref(j) )
  {
    j -= 3;
  }
  for ( k = v11;
        k != v9;
        nlohmann::json_abi_v3_11_3::detail::json_ref<nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector,std::string,bool,long,unsigned long,double,std::allocator,nlohmann::json_abi_v3_11_3::adl_serializer,std::vector<unsigned char>,void>>::~json_ref(k) )
  {
    k -= 24;
  }
  return a1;
}
```

The handler builds two key/value pairs via `nlohmann::json` ("message" and "version") and serializes them into the `Response` object. Hitting `/` returns this JSON. It’s present for sanity and isn’t directly related to the flag.

The middleware registration path:

```c
v13 = argv;
std::function<bool ()(akane::Context &)>::function<main::{lambda(akane::Context &)#2},void>(v12, &v13);
akane::Server::use(v4, v12);
```

Explanation. The critical detail is the capture: the lambda is constructed with `&v13`, where `v13` holds `argv`. In compiled C++, a capturing lambda stores its captures in a small heap/stack object—the "closure object". The framework later calls `operator()(closure_data, context)` so that the lambda can read its captures. That’s why, in the next snippet, the first argument is effectively the closure data. This is why "argv is in `a1` and context is in `a2`" in the decompiled signature: `a1` points to the lambda’s capture block (holding `argv`), and `a2` is the runtime request context.

The "debug" middleware (lambda #2):

```c
__int64 __fastcall main::{lambda(akane::Context &)#2}::operator()(_QWORD *a1, __int64 a2)
{
  char v2; // r13
  char v3; // r14
  char v5; // r13
  char v6; // r14
  akane::Response *v7; // rax
  bool v8; // [rsp+8h] [rbp-1C8h]
  bool v9; // [rsp+8h] [rbp-1C8h]
  _BYTE v10[47]; // [rsp+20h] [rbp-1B0h] BYREF
  char v11; // [rsp+4Fh] [rbp-181h] BYREF
  _BYTE v12[32]; // [rsp+50h] [rbp-180h] BYREF
  _BYTE v13[47]; // [rsp+70h] [rbp-160h] BYREF
  char v14; // [rsp+9Fh] [rbp-131h] BYREF
  _BYTE v15[47]; // [rsp+A0h] [rbp-130h] BYREF
  char v16; // [rsp+CFh] [rbp-101h] BYREF
  _BYTE v17[32]; // [rsp+D0h] [rbp-100h] BYREF
  _BYTE v18[47]; // [rsp+F0h] [rbp-E0h] BYREF
  char v19; // [rsp+11Fh] [rbp-B1h] BYREF
  _BYTE v20[32]; // [rsp+120h] [rbp-B0h] BYREF
  _BYTE v21[47]; // [rsp+140h] [rbp-90h] BYREF
  char v22; // [rsp+16Fh] [rbp-61h] BYREF
  char *v23; // [rsp+170h] [rbp-60h]
  char *v24; // [rsp+178h] [rbp-58h]
  char *v25; // [rsp+180h] [rbp-50h]
  char *v26; // [rsp+188h] [rbp-48h]
  char *v27; // [rsp+190h] [rbp-40h]
  int v28; // [rsp+19Ch] [rbp-34h]

  v2 = 0;
  v3 = 0;
  v27 = &v11;
  std::string::basic_string<std::allocator<char>>(v10, "X-Debug", &v11);
  v8 = 1;
  if ( (unsigned __int8)akane::Request::has_header(a2, v10) == 1 )
  {
    v26 = &v14;
    std::string::basic_string<std::allocator<char>>(v13, "X-Debug", &v14);
    v2 = 1;
    akane::Request::header(v12, a2, v13);
    v3 = 1;
    if ( (unsigned __int8)std::operator==<char>(v12, "true") == 1 )
      v8 = 0;
  }
  if ( v3 )
    std::string::~string(v12);
  if ( v2 )
    std::string::~string(v13);
  std::string::~string(v10);
  if ( v8 )
    return 1;
  v5 = 0;
  v6 = 0;
  v25 = &v16;
  std::string::basic_string<std::allocator<char>>(v15, "X-Debug-Index", &v16);
  v9 = 1;
  if ( (unsigned __int8)akane::Request::has_header(a2, v15) == 1 )
  {
    v24 = &v19;
    std::string::basic_string<std::allocator<char>>(v18, "X-Debug-Index", &v19);
    v5 = 1;
    akane::Request::header(v17, a2, v18);
    v6 = 1;
    if ( (unsigned int)(*(char *)std::string::operator[](v17, 0) - 48) <= 9 )
      v9 = 0;
  }
  if ( v6 )
    std::string::~string(v17);
  if ( v5 )
    std::string::~string(v18);
  std::string::~string(v15);
  if ( v9 )
    return 1;
  v23 = &v22;
  std::string::basic_string<std::allocator<char>>(v21, "X-Debug-Index", &v22);
  akane::Request::header(v20, a2, v21);
  v28 = std::stoi(v20, 0, 10);
  std::string::~string(v20);
  std::string::~string(v21);
  v7 = (akane::Response *)akane::Response::setStatus(a2 + 552, 200);
  akane::Response::setBody(v7, *(const char **)(8LL * v28 + *a1));
  return 0;
}
```

This middleware short-circuits the request and returns a body only if two headers are set. First, it requires `X-Debug: true` (string compare, lowercase). Second, it requires `X-Debug-Index` to begin with a digit; it then parses it as an integer. The crucial line is:

```c
akane::Response::setBody(r, *(const char **)(8*idx + *a1));
```

Here `a1` is the closure data. Because we captured `argv`, `*a1` is a `char **` pointing to `argv[0]`. Indexing `idx` elements from that base picks the `idx`-th pointer from the **startup vector** laid out by the kernel at process entry: an array of `argc` pointers to `argv[i]`, followed by a NULL, followed by an array of pointers to `envp[i]`, followed by a NULL, then the auxiliary vector. In practice, this means:

- `idx` within `[0, argc-1]` returns actual `argv[i]` strings.
- `idx == argc` returns NULL (bad body).
- `idx >= argc+1` starts returning `envp[0]`, `envp[1]`, ... which are strings like `"KEY=value"`.

Because the flag is explicitly stored in an environment variable, walking `idx` upward eventually lands on something like `INTECHFEST{...}`.

A proof-of-concept request:

```http
GET 127.0.0.1:5000
X-Debug: true
X-Debug-Index: 6
```
