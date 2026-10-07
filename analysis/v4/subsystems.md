# Subsystems (V4)

Counts are from string anchors and the call graph; membership is evidence-based, not exhaustive.

## nlib EXI/XML codec

32 functions reference their own `d:\cibuild\nlib\exi\...` source path (assert strings). Source units seen:

- ExiDecoder_cpp: 8 functions
- TextDecoder_cpp: 7 functions
- XmlStreamReaderInline_h: 4 functions
- ExiCoder_cpp: 3 functions
- ExiString_cpp: 2 functions
- BitByteStreamReader_h: 2 functions
- XmlExiStreamReader_cpp: 2 functions
- BitByteStreamReader_cpp: 2 functions
- ExiCoder_h: 1 functions
- XmlTextStreamReader_cpp: 1 functions

## NIM / shop control layer (log-string anchored, MEDIUM)

- `open_fs_user_session` @00103f00 - passes the service name "fs:USER" to the service-session open routine
- `shop_list_titles` @0022ae24 - trace log "Shop::ListTitles();"
- `shop_log_failure_reason` @0022b7c0 - maps NIM failure kinds to log text (Need System Update, Server is under Maintainance, Invalid Country...)
- `shop_log_download_failure_reason` @00230088 - same failure-text mapping plus download-specific cases (Title Already Downloaded, Task Already Exists)
- `shop_download_dtl` @002309a8 - logs "DTL downloaded successfully." / "DTL download failure"
- `npns_register_device` @00230d18 - log text "Register device to NPNS..." plus nn::npns::RegisterDeviceRequest error strings in the same function
- `title_set_tag_and_external_seed` @00235ef4 - logs SetTitleTag() / SetExternalSeed() / ExternalSeed already exists
- `parse_playable_date` @0030f5c0 - logs PARSE/GET PLAYABLE DATE FAILED
- `npns_unregister_device` @00319560 - log text "Unregister device from NPNS..." plus UnregisterDeviceRequest error strings
- `shop_initialize` @003233a8 - trace log InitializeForShop / Shop::SetApplicationId / SetTin / NeedsSystemUpdate
- `shop_unregister` @00323b68 - trace log "Shop::Unregister();"
- `shop_start_download_content` @00323c60 - trace logs RegisterTask / StartDownload / Download Content -> Failure/Cancel/SD Error
- `shop_download_tickets` @00324dd8 - trace log "nim::shop::DownloadTickets()"
- `shop_delete_credit_card_on_system_save_data` @00325068 - trace log "Shop::DeleteCreditCardOnSystemSaveData();"
- `shop_set_country` @003251b0 - trace log "Shop::SetCountry(%s);"
- `shop_get_balance` @00325cd0 - trace logs Shop::GetBalance / Shop::ListBalances
- `shop_delete_saved_credit_card` @00325e24 - trace log "Shop::DeleteSavedCreditCard();"
- `title_check_locked` @0037d4d8 - error log naming nn::fs::IsTitleLocked

## UI (layout panes)

1014 pane-name strings of the form `N_*_NN`/`P_*_NN`/`T_*_NN` (layout-pane lookups by name), e.g. N_root_00, N_nextPos_00, N_button_00, P_title_00, N_loadingIcon_00. Error UI uses `ErrorDialog_D_NN` and `error_txt01_NN` (46 strings). Layout archives such as `cad/TitleInfo.arc.lz`, `cad/Shelf.arc.lz` are referenced by name.
No UI function is named in V4: pane-name strings are used by hundreds of screens and do not by themselves identify a function.

## Graphics / media (strings only)

- `dmp_TexEnv[n].*`, `dmp_*` uniform/shader names: PICA200 shader uniform names (GPU state setup).
- `MoLive::*` strings: a movie/stream player library with its own allocator (error text "not enough memory", ReadEp stream messages).

## Runtime / library

- C runtime helpers named in S1 (strlen, strcpy, strcat, memcmp, strstr, snprintf, heap alloc/free wrappers, once guard) and `svc_*` wrappers for 3DS kernel calls.

