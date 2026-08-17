# Runs ${EXE} twice as separate processes and fails if the two KEM ciphertexts are identical.
#
# ML-KEM encapsulation must draw its 32-byte message m from a fresh CSPRNG, so two
# encapsulations to the SAME (fixed) public key in two separate processes must differ.
# Cross-process determinism means the RNG is a constant-seed stub (the mlkem-native test
# RNG) rather than a CSPRNG. This is the exact signature of that bug.
if(NOT EXE)
    message(FATAL_ERROR "run_encaps_entropy_twice.cmake requires -DEXE=<path to harness>")
endif()

execute_process(COMMAND "${EXE}" OUTPUT_VARIABLE OUT1 RESULT_VARIABLE RC1)
execute_process(COMMAND "${EXE}" OUTPUT_VARIABLE OUT2 RESULT_VARIABLE RC2)

if(NOT RC1 EQUAL 0 OR NOT RC2 EQUAL 0)
    message(FATAL_ERROR "encapsulation harness failed to run (rc1=${RC1} rc2=${RC2})")
endif()

string(STRIP "${OUT1}" OUT1)
string(STRIP "${OUT2}" OUT2)

if(OUT1 STREQUAL "")
    message(FATAL_ERROR "encapsulation harness produced empty output")
endif()

if(OUT1 STREQUAL OUT2)
    message(FATAL_ERROR
        "ML-KEM encapsulation is DETERMINISTIC across processes -- randomness is not a CSPRNG "
        "(constant-seed test RNG stub?). Two fresh processes produced the same ciphertext:\n${OUT1}")
endif()

message(STATUS "OK: two encapsulations to a fixed key differ across processes (CSPRNG confirmed)")
