# Nintendo 3DS eShop network findings

Source: `eshop_decompile_v3.txt` (Ghidra decompilation).

## Confirmed URL/host strings

The decompiler contains these URL host strings:

- `https://c.npns.app.nintendo.net` — referenced by `FUN_00207624 @ 0x00207624`.
- `https://tagaya.dev.ctr.cdn.nintendo.net` — referenced conditionally by `FUN_00320474 @ 0x00320474`.
- `https://tagaya.ctr.cdn.nintendo.net` — alternate production CDN URL referenced by the same function.
- `ninja.ctr.shop.nintendo.net` — present as a string and used as the `Origin` value in `FUN_00334190 @ 0x00334190`.

The last item is especially important: it is explicitly passed as the HTTP `Origin` header, so it is not merely an incidental string.

## eShop web-service families

A large group of request builders constructs paths containing:

- `/ninja_ws/...`
- `/samurai_ws/...`
- `/CCIF/services/credit_card...`

These are built with `FUN_002747e4` and then passed into the HTTP/request layer.

### Ninja service examples

Function | Decompiled string symbol
---|---
`FUN_00223dc8 @ 0x00223dc8` | `s__s_ninja_ws__s_tax_locations_lan_00223e4c`
`FUN_00227aac @ 0x00227aac` | `s__s_ninja_ws_my_transaction__llu__00227b0c`
`FUN_00262274 @ 0x00262274` | `s__s_ninja_ws_my_wishlist__llu__de_002622d4`
`FUN_00262310 @ 0x00262310` | `s__s_ninja_ws_my_wishlist__put_sho_00262360`
`FUN_0031ee60 @ 0x0031ee60` | `s__s_ninja_ws__s_title__llu_ec_inf_0031eed8`
`FUN_0031ef18 @ 0x0031ef18` | `s__s_ninja_ws_my_wishlist_notice_s_0031ef68`
`FUN_0031ef9c @ 0x0031ef9c` | `s__s_ninja_ws__s_title__014llu__re_0031f000`
`FUN_0031f150 @ 0x0031f150` | `s__s_ninja_ws_my_balance_current_s_0031f1a0`
`FUN_0031f1d4 @ 0x0031f1d4` | `s__s_ninja_ws_country__s_lang__s_s_0031f234`
`FUN_0031f2bc @ 0x0031f2bc` | `s__s_ninja_ws__s_title__llu_ec_inf_0031f334`
`FUN_0031f400 @ 0x0031f400` | `s__s_ninja_ws__s_title__llu__purch_0031f464`
`FUN_0031f4a0 @ 0x0031f4a0` | wishlist sort endpoints
`FUN_0031f624 @ 0x0031f624` | wishlist notice endpoint
`FUN_0031f79c @ 0x0031f79c` | credit-card shop endpoint
`FUN_0031f820 @ 0x0031f820` | NPNS status shop endpoint
`FUN_0031f8a0 @ 0x0031f8a0` | language/shop-id endpoint
`FUN_0031f920 @ 0x0031f920` | coupon check endpoint
`FUN_0031f9ac @ 0x0031f9ac` | movie play endpoint
`FUN_0031fa3c @ 0x0031fa3c` | title pre-purchase endpoint
`FUN_0031fb1c @ 0x0031fb1c` | votes/shop-id endpoint
`FUN_0031fbbc @ 0x0031fbbc` | session open endpoint
`FUN_0031fc34 @ 0x0031fc34` | tax-location endpoint
`FUN_0031ff28 @ 0x0031ff28` | owned-coupons endpoint
`FUN_0031ffc8 @ 0x0031ffc8` | public title statistics endpoint
`FUN_00320104 @ 0x00320104` | demo purchase endpoint
`FUN_003201a0 @ 0x003201a0` | votes PUT endpoint
`FUN_00320298 @ 0x00320298` | session close endpoint
`FUN_00320378 @ 0x00320378` | title-id/language-pair endpoint
`FUN_00320598 @ 0x00320598` | balance/current endpoint
`FUN_00320688 @ 0x00320688` | wishlist merge endpoint
`FUN_00320aa0 @ 0x00320aa0` | shared title IDs endpoint
`FUN_00320b28 @ 0x00320b28` | tax-location PUT endpoint
`FUN_00320bb0 @ 0x00320bb0` | owned coupons/shop endpoint
`FUN_00320c34 @ 0x00320c34` | votes DELETE endpoint
`FUN_00320cb8 @ 0x00320cb8` | redeemable-card check endpoint
`FUN_00320f30 @ 0x00320f30` | loyalty-account endpoint
`FUN_00320fbc @ 0x00320fbc` | credit-card DELETE endpoint
`FUN_00321044 @ 0x00321044` | votes migration endpoint
`FUN_003212b0 @ 0x003212b0` | tax-location DELETE endpoint
`FUN_00321a6c @ 0x00321a6c` | loyalty-account endpoint
`FUN_00321af8 @ 0x00321af8` | parental-control endpoint
`FUN_00321b84 @ 0x00321b84` | loyalty-account status endpoint
`FUN_00321c08 @ 0x00321c08` | votable-titles endpoint
`FUN_00321d8c @ 0x00321d8c` | session-open-with-... endpoint

## Samurai service examples

The same request-building layer contains `/samurai_ws/...` families for:

- titles
- movies
- rankings
- genres
- news
- telops
- directory
- languages
- contents
- search categories
- publishers

Examples:

- `FUN_0032078c @ 0x0032078c` — title/language request.
- `FUN_00320840 @ 0x00320840` — movie/shop request.
- `FUN_003208f4 @ 0x003208f4` — rankings/shop request.
- `FUN_00320994 @ 0x00320994` — genres/language request.
- `FUN_00320dbc @ 0x00320dbc` — contents/language request.
- `FUN_00321130 @ 0x00321130` — search-category request.
- `FUN_003213a0 @ 0x003213a0` — movies/language request.
- `FUN_003219d0 @ 0x003219d0` — publishers/language request.

## Request/authentication details

`FUN_002076d8 @ 0x002076d8` shows a generic HTTP request setup that:

1. Sets a `User-Agent`.
2. Sets `Content-Type: application/x-www-form-urlencoded`.
3. Adds a `service_token` parameter.
4. Adds a `device_id` parameter.
5. Uses either an initial-token path or an existing-token path depending on state.

There is also a separate request path around `FUN_00340cf8` that sets an `X-Nintendo-ServiceToken` HTTP header.

The decompile also shows `Origin: ninja.ctr.shop.nintendo.net` being set in `FUN_00334190`.

## Important interpretation

The dump is clearly more than a simple content downloader. It contains a fairly large HTTP API client with distinct Ninja and Samurai service namespaces and stateful session/service-token handling.

The endpoint names above are derived from Ghidra-generated string-symbol names. Ghidra's symbol naming loses some punctuation/separator information, so the exact URL formatting should be reconstructed from the underlying string data or the original binary rather than treating every underscore in a symbol name as a literal underscore.

## Next investigation targets

1. Locate where the `DAT_*` base-URL pointers used by the Ninja/Samurai request builders are initialized.
2. Recover the exact literal URL templates behind the `s__s_ninja_ws...` and `s__s_samurai_ws...` symbols.
3. Trace the generic HTTP functions (`FUN_002540xx` family) to determine how headers, POST bodies, responses, and status codes are handled.
4. Map the session/service-token flow and identify which requests require existing session state.
5. Map the CDN/content path separately from the web-service API.

This document intentionally records observed behavior only; it does not attempt to bypass Nintendo authentication or access paid content.
