"""
  
  Copyright (c) 2004 Dug Song <dugsong@monkey.org>
  All rights reserved, all wrongs reversed.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. The names of the authors and copyright holders may not be used to
     endorse or promote products derived from this software without
     specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  Copyright (c) 2014 Sebastian Block <basti@linux-source.de>
  Make dpkt usable under python 3. 
"""

"""Simple packet creation and parsing."""

import copy 
import struct

class Error(Exception): pass
class UnpackError(Error): pass
class NeedData(UnpackError): pass
class PackError(Error): pass

""" Generic Metaclass for Packet """
class MetaPacket(type):
    def __new__(cls, clsname, clsbases, clsdict):
        t = type.__new__(cls, clsname, clsbases, clsdict)
        st = getattr(t, '__hdr__', None)
        if st is not None:
            # __slots__ only created in __new__()
            clsdict['__slots__'] = [ x[0] for x in st ] + [ 'data' ]
            t = type.__new__(cls, clsname, clsbases, clsdict)
            t.__hdr_fields__ = [ x[0] for x in st ]
            t.__hdr_fmt__ = getattr(t, '__byte_order__', '>') + \
                    ''.join([ x[1] for x in st ])
            t.__hdr_len__ = struct.calcsize(t.__hdr_fmt__)
            t.__hdr_defaults__ = dict(zip(
                t.__hdr_fields__, [ x[2] for x in st ]))
        return t

""" Base class for all packets """
class Packet(metaclass=MetaPacket):
    __metaclass__ = MetaPacket  # this was for python 2.x

    def __init__(self, *args, **kwargs):
        """Packet constructor with ([buf], [field=val,...]) prototype.
        
        Arguments:
        buf -- optional packet buffer to unpack

        Optional keyword arguments correspond to members to set
        (matching fields in self.__hdr__, or 'data').
        """
        self.data = b""
        if args:
            try:
                self.unpack(args[0])
            except struct.error:
                if len(args[0]) < self.__hdr_len__:
                    raise NeedData
                raise UnpackError('invalid %s: %r' %
                                  (self.__class__.__name__, args[0]))
        else:
            for k in self.__hdr_fields__:
                setattr(self, k, copy.copy(self.__hdr_defaults__[k]))
            for k, v in kwargs.items():
                setattr(self, k, v)

    def __len__(self):
        return self.__hdr_len__ + len(self.data)

    def __getitem__(self, k):
        try: return getattr(self, k)
        except AttributeError: raise KeyError

    def __repr__(self):
        l = [ '%s=%r' % (k, getattr(self, k))
             for k in self.__hdr_defaults__
             if getattr(self, k) != self.__hdr_defaults__[k] ]
        if self.data:
            l.append('data=%r' % self.data)
        return '%s(%s)' % (self.__class__.__name__, ', '.join(l))

    def __str__(self):
        return str(self.pack_hdr()) + str(self.data)

    def pack_hdr(self):
        """Return packed header string."""
        try:
            return struct.pack(self.__hdr_fmt__,
                               *[ getattr(self, k) for k in self.__hdr_fields__ ])
        except struct.error:
            vals = []
            for k in self.__hdr_fields__:
                v = getattr(self, k)
                if isinstance(v, tuple):
                    vals.extend(v)
                else:
                    vals.append(v)
            try:
                return struct.pack(self.__hdr_fmt__, *vals)
            except struct.error as e:
                raise PackError(str(e))

    def pack(self):
        """Return packed header + self.data as bytes"""
        ret = self.pack_hdr()
        if str == type(self.data):
            ret += self.data.encode()
        elif bytes == type(self.data):
            ret += self.data
        else:
            try:
                tmp = self.data.pack()
            except:
                tmp = None
            else:
                ret += tmp
        return ret

    def unpack(self, buf):
        """Unpack packet header fields from buf, and set self.data."""
        for k, v in zip(self.__hdr_fields__,
                                   struct.unpack(self.__hdr_fmt__, buf[:self.__hdr_len__])):
            setattr(self, k, v)
        self.data = buf[self.__hdr_len__:]

    def printHdr(self):
        for k in self.__hdr_fields__:
            v = getattr(self, k)
            print(k,type(v),v)

