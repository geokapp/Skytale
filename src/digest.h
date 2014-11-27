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
#ifndef DIGEST_H
#define DIGEST_H

#include <string>
#include "common.h"

namespace Skytale {

/**
 * MessageDigest - An object that creates and verifies a message digest.
 *
 * This class defines the Dike Message Digest object. To create a new object call
 * the constructor.
 */
class MessageDigest {
 public:
  std::string make(const char *message_cstr);
  bool verify(const char *message_with_digest_cstr);
  std::string hash(const HashFunction hash_func, const char *message_cstr);
  
};

}

#endif


