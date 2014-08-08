// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Skytale - A high-level cryptographic and authentication library.
 *
 * Copyright (C) 2014 Giorgos Kappes <geokapp@gmail.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file LICENSE.
 * 
 */
#ifndef COMMON_H
#define COMMON_H

namespace Skytale {

enum HashFunction
{
  SHA256_H,
  SHA384_H,
  SHA512_H,
  RIPEMD128_H,
  RIPEMD160_H,
  RIPEMD256_H,
  RIPEMD320_H,
  MD5_H,
  CRC32_H
};

}


#endif


