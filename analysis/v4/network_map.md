# Network subsystem map (V4)

Every row cites its evidence; names are in `function_names.csv` with confidence. Confidence MEDIUM means purpose inferred from strings/callers, not proven.

## Hosts, base URLs and fixed URLs found as strings

| string address | string | referencing functions |
|---|---|---|
| 001ff87c | `http://www.w3.org/XML/1998/namespace` | nlib_exi_ExiCoder_cpp_001ff504 |
| 001ff8c4 | `http://www.w3.org/2001/XMLSchema-instance` | nlib_exi_ExiCoder_cpp_001ff504 |
| 00207654 | `https://%c-npns.app.nintendo.net/api/v1/` | build_npns_api_url |
| 0031edec | `https://` | FUN_0031ed98, FUN_00321e08 |
| 00320520 | `https://tagaya-ctr.cdn.nintendo.net/tagaya/versionlist` | build_tagaya_versionlist_url |
| 0032055c | `https://tagaya-dev-ctr.cdn.nintendo.net/tagaya/versionlist` | build_tagaya_versionlist_url |
| 00334380 | `ninja.ctr.shop.nintendo.net` | http_set_origin_header |
| 0038aefc | `https://samurai.ctr.shop.nintendo.net` | init_shop_service_host_urls |
| 0038af30 | `https://ninja.ctr.shop.nintendo.net` | init_shop_service_host_urls |
| 0038af58 | `https://ccif.ctr.shop.nintendo.net` | init_shop_service_host_urls |
| 0038af80 | `https://eou.c.shop.nintendowifi.net` | init_shop_service_host_urls |
| 003bab00 | `http://` | FUN_0020c58c |
| 003bab08 | `https://` | FUN_0020c58c |
| 003d0c4d | `",                 "phone_number":"0570-012-789",                 "url":"http://www.d3p.co` | (data table / no direct code xref) |
| 003d1440 | `https://ninja` | (data table / no direct code xref) |
| 003d1450 | `https://tagaya.wup.shop.nintendo.net/tagaya_ctr/dev/tiger/versionlist%d` | build_tagaya_versionlist_url |
| 003d14f4 | `https://ccif` | (data table / no direct code xref) |
| 003d1504 | `https://samurai` | (data table / no direct code xref) |
| 003d1bec | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/7RW9z5Cb71F` | (data table / no direct code xref) |
| 003d1c5c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/vD1Tyxppgpt` | (data table / no direct code xref) |
| 003d1ccc | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/CtfKXACbUPl` | (data table / no direct code xref) |
| 003d1d3c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d1dac | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/kRlrRG3XMEZ` | (data table / no direct code xref) |
| 003d1e1c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/7RW9z5Cb71F` | (data table / no direct code xref) |
| 003d1e8c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/vD1Tyxppgpt` | (data table / no direct code xref) |
| 003d1efc | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/CtfKXACbUPl` | (data table / no direct code xref) |
| 003d1f6c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d1fdc | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/kRlrRG3XMEZ` | (data table / no direct code xref) |
| 003d204c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/7RW9z5Cb71F` | (data table / no direct code xref) |
| 003d20bc | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/kRlrRG3XMEZ` | (data table / no direct code xref) |
| 003d212c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d219c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d220c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/CtfKXACbUPl` | (data table / no direct code xref) |
| 003d227c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d22ec | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d235c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/vD1Tyxppgpt` | (data table / no direct code xref) |
| 003d23cc | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/CtfKXACbUPl` | (data table / no direct code xref) |
| 003d243c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d24ac | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/CtfKXACbUPl` | (data table / no direct code xref) |
| 003d251c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d258c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d25fc | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/CtfKXACbUPl` | (data table / no direct code xref) |
| 003d266c | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d26dc | `https://a248.e.akamai.net/f/248/103046/10m/npdl.c.app.nintendowifi.net/p01/nsa/AH3oZwrEbne` | (data table / no direct code xref) |
| 003d4a38 | `https://samurai.wup.shop.nintendo.net/samurai/image/rating_system/201/ja/rating/1/icon` | FUN_0038963c, FUN_0038a3f0 |
| 003d4a90 | `https://samurai.wup.shop.nintendo.net/samurai/image/rating_system/201/ja/rating/6/icon` | FUN_0038963c, FUN_0038a3f0 |
| 003d4ae8 | `https://samurai.wup.shop.nintendo.net/samurai/image/JP/ja/movie/50040000000026/icon` | FUN_0038963c, FUN_0038a3f0 |
| 003d4b3c | `https://samurai.wup.shop.nintendo.net/samurai/image/JP/ja/movie/50040000000026/banner` | FUN_0038963c, FUN_0038a3f0 |
| 003d5225 | `","id":190},"rating_info":{"rating_system":{"name":"CERO","id":201},"rating":{"icon_url":"` | (data table / no direct code xref) |

## HTTP header and cookie strings

| string | referencing functions |
|---|---|
| `Cookie` @001df0d8 | FUN_001ded48 |
| `User-Agent` @00207a20 | FUN_002076d8 |
| `Content-Type` @00207a2c | FUN_002076d8 |
| `User-Agent` @00207ce8 | FUN_00207ae4 |
| `Content-Range` @0031a380 | FUN_00319d38 |
| `Content-Range` @0031b6e4 | FUN_0031b138 |
| `User-Agent` @0031c59c | FUN_0031c1c8 |
| `Referer` @0031c5ac | FUN_0031c1c8 |
| `Accept` @0031de0c | FUN_0031dd60 |
| `Cookie` @0031e448 | FUN_0031e3e8 |
| `Origin` @0033439c | http_set_origin_header |
| `X-Nintendo-ServiceToken` @00341750 | http_set_service_token_header |
| `Set-Cookie` @003803d0 | FUN_00380364 |

## Endpoint request builders (MEDIUM: function formats exactly one service URL with snprintf)

Method hints come from the path markers in the format string (`!put`, `!delete`, `!purchase` ...); the HTTP verb itself is chosen by the caller and was not traced.

### Session / account

| function | address | callers | URL format |
|---|---|---|---|
| `build_url_ninja_ws_my_account_ctr_migrate_without_nna` | 0031f268 | 1 | `%s/ninja/ws/my/account/ctr/!migrate_without_nna?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_loyalty_account` | 00321b84 | 1 | `%s/ninja/ws/my/loyalty_account?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_loyalty_account_link` | 00320f30 | 1 | `%s/ninja/ws/my/loyalty_account/!link?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_loyalty_account_unlink` | 00321a6c | 1 | `%s/ninja/ws/my/loyalty_account/!unlink?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_session_close` | 00320298 | 1 | `%s/ninja/ws/my/session/!close?_type=json` |
| `build_url_ninja_ws_my_session_open` | 0031fbbc | 1 | `%s/ninja/ws/my/session/!open?_type=json` |
| `build_url_ninja_ws_my_session_open_without_nna` | 00321d8c | 1 | `%s/ninja/ws/my/session/!open_without_nna` |
| `build_url_ninja_ws_my_votes_migrate_ctr` | 00321044 | 1 | `%s/ninja/ws/my/votes/!migrate_ctr?shop_id=1&_type=json` |

### Wishlist

| function | address | callers | URL format |
|---|---|---|---|
| `build_url_ninja_ws_my_wishlist_ID_delete` | 00262274 | 2 | `%s/ninja/ws/my/wishlist/%llu/!delete?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_wishlist_merge` | 00320688 | 1 | `%s/ninja/ws/my/wishlist/!merge?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_wishlist_notice` | 0031ef18 | 1 | `%s/ninja/ws/my/wishlist/notice?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_wishlist_notice_ack` | 0031f624 | 1 | `%s/ninja/ws/my/wishlist/notice/!ack?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_wishlist_put` | 00262310 | 2 | `%s/ninja/ws/my/wishlist/!put?shop_id=1&_type=json` |

### Balance / payment instruments

| function | address | callers | URL format |
|---|---|---|---|
| `build_url_ccif_services_credit_card_input` | 00320a2c | 1 | `%s/CCIF/services/credit_card/!input` |
| `build_url_ninja_ws_country_ID_replenish_amounts` | 003210cc | 1 | `%s/ninja/ws/country/%s/replenish_amounts?lang=%s&shop_id=1&_type=json` |
| `build_url_ninja_ws_my_auto_billing_ID_cancel` | 003211d0 | 1 | `%s/ninja/ws/my/auto_billing/%014llu/!cancel?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_auto_billing_plans` | 00320ecc | 1 | `%s/ninja/ws/my/auto_billing/plans?limit=%u&offset=%u&shop_id=1&_typ...` |
| `build_url_ninja_ws_my_balance_current` | 0031f150 | 1 | `%s/ninja/ws/my/balance/current?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_balance_current_cc_add` | 00320598 | 1 | `%s/ninja/ws/my/balance/current/!cc_add?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_credit_card` | 0031f79c | 1 | `%s/ninja/ws/my/credit_card/?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_credit_card_delete` | 00320fbc | 1 | `%s/ninja/ws/my/credit_card/!delete?shop_id=1&_type=json` |
| `build_url_ninja_ws_redeemable_card_check` | 00320cb8 | 1 | `%s/ninja/ws/redeemable_card/!check?shop_id=1&_type=json` |

### Coupons

| function | address | callers | URL format |
|---|---|---|---|
| `build_url_ninja_ws_ID_coupon_check` | 0031f920 | 1 | `%s/ninja/ws/%s/coupon/!check?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_owned_coupons` | 0031ff28 | 1 | `%s/ninja/ws/my/owned_coupons?ns_uid=%llu&shop_id=1&_type=json` |
| `build_url_ninja_ws_my_owned_coupons` | 00320bb0 | 1 | `%s/ninja/ws/my/owned_coupons?shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_coupon_ID_titles` | 00321c90 | 1 | `%s/samurai/ws/%s/coupon/%llu/titles?lang=%s&limit=%u&offset=%u&shop...` |

### Purchase / transactions / receipts

| function | address | callers | URL format |
|---|---|---|---|
| `build_url_ninja_ws_ID_demo_ID_purchase` | 00320104 | 1 | `%s/ninja/ws/%s/demo/%llu/!purchase?shop_id=1&_type=json` |
| `build_url_ninja_ws_ID_title_ID_ec_info` | 0031ee60 | 1 | `%s/ninja/ws/%s/title/%llu/ec_info?shop_id=1&lang=%s&_type=json` |
| `build_url_ninja_ws_ID_title_ID_ec_info` | 0031f2bc | 1 | `%s/ninja/ws/%s/title/%llu/ec_info?lang=%s&shop_id=1&_type=json` |
| `build_url_ninja_ws_ID_title_ID_purchase` | 0031f400 | 1 | `%s/ninja/ws/%s/title/%llu/!purchase?shop_id=1&_type=json` |
| `build_url_ninja_ws_ID_title_ID_redeem` | 0031ef9c | 1 | `%s/ninja/ws/%s/title/%014llu/!redeem?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_abandoned_transaction_ID_receipt` | 00320e54 | 1 | `%s/ninja/ws/my/abandoned_transaction/%llu/receipt?tracing_transacti...` |
| `build_url_ninja_ws_my_abandoned_transactions` | 00321d14 | 1 | `%s/ninja/ws/my/abandoned_transactions?tracing_transaction_id=%llu&l...` |
| `build_url_ninja_ws_my_transaction_ID_receipt` | 00227aac | 2 | `%s/ninja/ws/my/transaction/%llu/receipt?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_transactions` | 00320410 | 1 | `%s/ninja/ws/my/transactions?limit=%u&offset=%u&shop_id=1&_type=json` |

### Votes

| function | address | callers | URL format |
|---|---|---|---|
| `build_url_ninja_ws_my_votes` | 0031fb1c | 1 | `%s/ninja/ws/my/votes?shop_id=1&limit=%u&offset=%u&_type=json` |
| `build_url_ninja_ws_my_votes_delete` | 00320c34 | 1 | `%s/ninja/ws/my/votes/!delete?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_votes_put` | 003201a0 | 1 | `%s/ninja/ws/my/votes/!put?shop_id=1&_type=json` |

### Shared / recommended titles

| function | address | callers | URL format |
|---|---|---|---|
| `build_url_ninja_ws_my_recommend_title` | 00320220 | 1 | `%s/ninja/ws/my/recommend_title?directory_id=%llu&friend_code=%016ll...` |
| `build_url_ninja_ws_my_shared_title_ids` | 00320aa0 | 1 | `%s/ninja/ws/my/shared_title_ids?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_shared_titles` | 00320314 | 1 | `%s/ninja/ws/my/shared_titles?limit=%u&offset=%u&shop_id=1&_type=json` |
| `build_url_ninja_ws_my_votable_titles` | 00320624 | 1 | `%s/ninja/ws/my/votable_titles?shop_id=1&limit=%u&offset=%u&_type=json` |
| `build_url_ninja_ws_my_votable_titles_put` | 00321c08 | 1 | `%s/ninja/ws/my/votable_titles/!put?shop_id=1&_type=json` |

### Catalog (titles, directories, rankings, search)

| function | address | callers | URL format |
|---|---|---|---|
| `build_url_ninja_ws_ID_movie_ID_play` | 0031f9ac | 1 | `%s/ninja/ws/%s/movie/%llu/!play?shop_id=1` |
| `build_url_ninja_ws_ID_title_public_status` | 0031ffc8 | 1 | `%s/ninja/ws/%s/title/public_status?lang=%s&shop_id=1&_type=json` |
| `build_url_ninja_ws_ID_titles_online_prices` | 0031fec4 | 1 | `%s/ninja/ws/%s/titles/online_prices?title%%5B%%5D=%s&lang=%s&includ...` |
| `build_url_ninja_ws_ID_titles_online_prices` | 00321234 | 1 | `%s/ninja/ws/%s/titles/online_prices?title%%5B%%5D=%s&lang=%s&includ...` |
| `build_url_ninja_ws_titles_id_pair` | 00320378 | 1 | `%s/ninja/ws/titles/id_pair?lang=%s&title_id%%5B%%5D=%s` |
| `build_url_samurai_ws_ID_contents` | 00320dbc | 1 | `%s/samurai/ws/%s/contents?lang=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_directories` | 0032070c | 1 | `%s/samurai/ws/%s/directories?lang=%s&pattern=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_genres` | 00320994 | 1 | `%s/samurai/ws/%s/genres?lang=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_languages` | 0031fdf4 | 1 | `%s/samurai/ws/%s/languages?lang=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_movie_ID` | 00320840 | 1 | `%s/samurai/ws/%s/movie/%llu?shop_id=1&lang=%s&_type=json` |
| `build_url_samurai_ws_ID_movies` | 003213a0 | 1 | `%s/samurai/ws/%s/movies?lang=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_news` | 0031f0bc | 1 | `%s/samurai/ws/%s/news?lang=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_publishers` | 003219d0 | 1 | `%s/samurai/ws/%s/publishers?lang=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_publishers_contacts` | 0032133c | 1 | `%s/samurai/ws/%s/publishers/contacts?shop_id=1&lang=%s&_type=json` |
| `build_url_samurai_ws_ID_ranking_ID` | 0031f6b0 | 1 | `%s/samurai/ws/%s/ranking/%u?shop_id=1&limit=%u&offset=%u&lang=%s&_t...` |
| `build_url_samurai_ws_ID_rankings` | 003208f4 | 1 | `%s/samurai/ws/%s/rankings?shop_id=1&device=4&lang=%s&_type=json` |
| `build_url_samurai_ws_ID_searchcategory` | 00321130 | 1 | `%s/samurai/ws/%s/searchcategory?lang=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_telops` | 0031f58c | 1 | `%s/samurai/ws/%s/telops?lang=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_title_ID` | 0032078c | 1 | `%s/samurai/ws/%s/title/%llu?lang=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_title_ID_aocs` | 00320d40 | 1 | `%s/samurai/ws/%s/title/%014llu/aocs?lang=%s&shop_id=1&_type=json` |
| `build_url_samurai_ws_ID_titles` | 00227c54 | 3 | `%s/samurai/ws/%s/titles?lang=%s&shop_id=1&_type=json` |

### Shop configuration (country, tax, language, hosts)

| function | address | callers | URL format |
|---|---|---|---|
| `build_url_ninja_ws_ID_tax_locations` | 00223dc8 | 1 | `%s/ninja/ws/%s/tax_locations?lang=%s&shop_id=1&_type=json` |
| `build_url_ninja_ws_country_ID` | 0031f1d4 | 1 | `%s/ninja/ws/country/%s?lang=%s&shop_id=1&_type=json` |
| `build_url_ninja_ws_my_language` | 0031f8a0 | 1 | `%s/ninja/ws/my/language?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_tax_location` | 0031fc34 | 1 | `%s/ninja/ws/my/tax_location?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_tax_location_delete` | 003212b0 | 1 | `%s/ninja/ws/my/tax_location/!delete?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_tax_location_put` | 00320b28 | 1 | `%s/ninja/ws/my/tax_location/!put?shop_id=1&_type=json` |
| `build_url_ninja_ws_service_hosts` | 0031edfc | 1 | `%s/ninja/ws/service_hosts?country=%s&lang=%s&shop_id=1&_type=json` |

### Other

| function | address | callers | URL format |
|---|---|---|---|
| `build_url_ninja_ws_my_npns_status` | 0031f820 | 1 | `%s/ninja/ws/my/npns_status?shop_id=1&_type=json` |
| `build_url_ninja_ws_my_parental_control_put` | 00321af8 | 1 | `%s/ninja/ws/my/parental_control/!put?shop_id=1&_type=json` |
| `build_url_samurai_layout_rating_info_ID_ID_layout` | 0031f374 | 1 | `%s/samurai/layout/rating_info/%d_%s.layout` |

## URL-path classifiers (strstr on the request URL; reached through pointer tables, no direct callers)

count: 8

- `url_find_path_ccif_credit_card_input` @003222c0
- `url_find_path_cp3s_contentset_n` @00322230
- `url_find_path_ninja_my_balance_current_cc_add` @00322450
- `url_find_path_ninja_my_balance_current_cc_prepare` @00322498
- `url_find_path_ninja_my_balance_current_wallet_add` @003224e0
- `url_find_path_ninja_my_credit_card` @00322278
- `url_find_path_ninja_my_credit_card_delete` @00322378
- `url_find_path_ninja_my_votes` @003221e8

## Shared layers observed

- `snprintf` @002747e4: formats every URL (callers pass `%s/ninja/ws/...`, `%s/samurai/ws/...`, `%s/CCIF/...`; first %s argument is a base-host string held in a global at 0x003e1da8).
- Builders end by constructing a string object from the C string (`FUN_002a8e48`-style copy-construct) into their first parameter: the URL is *returned by output parameter*, the request itself is issued elsewhere.
- Service hosts: the production host URLs `https://samurai.ctr.shop.nintendo.net`, `https://ninja.ctr.shop.nintendo.net`, `https://ccif.ctr.shop.nintendo.net`, `https://eou.c.shop.nintendowifi.net` are all referenced by one function (`init_shop_service_host_urls` @0038ae7c); the builders take the active base host from a global (0x003e1da8).
- Tagaya: `https://tagaya-ctr.cdn.nintendo.net/tagaya/versionlist` (prod) / `tagaya-dev-ctr` (dev) chosen in one function; a second hard-coded `tagaya.wup.shop.nintendo.net/tagaya_ctr/dev/tiger/versionlist%d` form also exists. (analysis/NETWORK.md listed `tagaya.ctr.cdn...`; the binary string is `tagaya-ctr.cdn...`.)
- NPNS: `https://%c-npns.app.nintendo.net/api/v1/` built by one function; register/unregister flows log through `nn::npns::*Request` messages and use `nn::act::AcquireIndependentServiceToken`.
- Authentication: header `X-Nintendo-ServiceToken` is set from a token object; `Cookie`/`Set-Cookie` are copied through a header-lookup helper; `Origin: ninja.ctr.shop.nintendo.net` is set explicitly.
- TLS: no certificate/verification strings were identified in this binary (the HTTPS stack is the system `httpc`/`ssl` services); this was not traced further.

## Not established

- The HTTP method used for each endpoint, the request object lifecycle and the JSON field parsers were not traced to named functions.
