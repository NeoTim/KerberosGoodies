#!/usr/bin/env python2.5
#Copyright (C) 1998 by the FundsXpress, INC.
#
#All rights reserved.
#
#Export of this software from the United States of America may require
#a specific license from the United States Government.  It is the
#responsibility of any person or organization contemplating export to
#obtain such a license before exporting.
#
#WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
#distribute this software and its documentation for any purpose and
#without fee is hereby granted, provided that the above copyright
#notice appear in all copies and that both that copyright notice and
#this permission notice appear in supporting documentation, and that
#the name of FundsXpress. not be used in advertising or publicity pertaining
#to distribution of the software without specific, written prior
#permission.  FundsXpress makes no representations about the suitability of
#this software for any purpose.  It is provided "as is" without express
#or implied warranty.
#
#THIS SOFTWARE IS PROVIDED ``AS IS AND WITHOUT ANY EXPRESS OR
#IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
#WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#
#Python port from MIT Kerberos lib/crypto/nfold.c by Stefan Roggensack

from array import array

def leastCommonMultiple(a,b):
    """
    Compute the Least Common Multiple (lcm) of two numbers.
    Using the euclidean algorithm
    """
    temp = a*b
    while(b != 0):
        c = b
        b = a%b
        a = c
    return temp/a

def krb5_nfold(password, outlength):
    """
    n-fold(k-bits):
    l = lcm(n,k)
    r = l/k
    s = k-bits | k-bits rot 13 | k-bits rot 13*2 | ... | k-bits rot 13*(r-1)
    compute the 1's complement sum:
    n-fold = s[0..n-1]+s[n..2n-1]+s[2n..3n-1]+..+s[(k-1)*n..k*n-1]
    """

    if isinstance(password, str):
        # Use a Array of ordinal Numbers (this should only be lower then 256)
        password = array('B', map(ord, password))
    inlength = len(password)

    # first compute lcm(n,k)
    lcm = leastCommonMultiple(inlength,outlength)
    # now do the real work

    byte = 0
    out = array('B', chr(0)*outlength)

    # this will end up cycling through k lcm(k,n)/k times, which
    #   is correct
    for i in xrange(lcm-1,-1,-1):
        #compute the msbit in k which gets added into this byte
        msbit = (#first, start with the msbit in the first, unrotated byte
                ((inlength<<3)-1)
                # then, for each byte, shift to the right for each repetition
                + (((inlength<<3)+13)*(i/inlength))
                # last, pick out the correct byte within that shifted repetition
                +((inlength-(i%inlength))<<3)
                )%(inlength<<3)
        # pull out the byte value itself
        byte += (((password[((inlength-1)-(msbit>>3))%inlength]<<8)|
                  (password[((inlength)-(msbit>>3))%inlength]))
                  >>((msbit&7)+1))&0xff

        # do the addition
        byte += out[i%outlength]
        out[i%outlength] = byte&0xff

        # keep around the carry bit, if any
        byte >>= 8

    # if there's a carry bit left over, add it back in
    if byte != 0:
        for i in xrange(outlength-1,0,-1):
            # do the addition
            byte += out[i]
            out[i] = byte&0xff

            #  keep around the carry bit, if any
            byte >>= 8
    return out.tostring()
