# Roadmap (prioritised)

1. **Decide the object-model strategy** (audit §6): `-m32` vs explicit guest-pointer layouts. Prototype on `section_find_fourcc` + `FUN_0029b380`.
2. **Get a disassembly-first workflow**: extend `oracle_vectors.py` to run functions with prepared guest memory (structs) so object-based routines can be differentially tested too.
3. Recover message-catalog loading (`message_file_create`, `section_find_fourcc`, `message_lookup_text` signature fix).
4. Identify the application main loop: trace from `runtime_entry` through `FUN_00103e1c/00104db0/00102520`.
5. Layout engine (`layout_find_*pane*`, BCLYT/BCLAN/BCLIM/BCFNT parsers). **Needs layout assets from the owner's own console dump** – never downloaded by the project.
6. PICA200 command-list translation to the software/OpenGL renderer.
7. Networking: separate request builders (`/ninja_ws`, `/samurai_ws`) from `http:C`; replace transport with a documented catalog protocol and legal sample data. No account/payment/ownership bypass.
8. Compat services: threads/mutex/event, `fs:USER` archives, `cfg:u`, `APT`.
9. ARM64 build once step 1 is settled.

# What actually runs today

`eshop` opens an SDL window (SDL2 here; SDL3 preferred when installed) containing both screens, integer or fit scaling, mouse→touch mapping, keyboard→button mapping, fullscreen.
It displays a **bring-up screen (substitute UI)** whose string handling goes through 7 reconstructed original routines. Headless mode renders to PPM for testing.
The original eShop UI, logic flow, networking and rendering are **not** running.
