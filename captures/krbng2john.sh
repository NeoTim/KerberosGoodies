#!/usr/bin/env bash

tshark -S "" -r "$1" -T fields -e kerberos.PA_ENC_TIMESTAMP.encrypted | sed -e 's,:,,g'| grep . > thash
beros  awk '{print substr($1,1,88)}' thash
2a0e68168d1eac344da458599c3a2b33ff326a061449fcbc242b212504e484d45903c6a16e2d593912f56c93
➜  Kerberos  awk '{print substr($1,89,24)}' thash
883bf697b325193d62a8be9c

