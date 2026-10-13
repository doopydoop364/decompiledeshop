# eshop Linux port (work in progress)

    cmake -S linux-port -B linux-port/build            # add -DESHOP_SANITIZE=ON for ASan+UBSan
    cmake --build linux-port/build -j
    ctest --test-dir linux-port/build --output-on-failure
    linux-port/build/eshop [--headless --frames N --dump out.ppm] [--scale N] [--fit] [--fullscreen]

Keys: X=A Z=B S=X A=Y Q=L W=R Enter=Start RShift=Select arrows=D-pad, mouse on lower screen = touch, Esc quits.
Regenerating test vectors (needs `pip install unicorn capstone`):
`python3 -I linux-port/tools/oracle_vectors.py code_decompressed.bin linux-port/tests/vectors`

See `docs/` for the audit, function status, compat layer and roadmap.
