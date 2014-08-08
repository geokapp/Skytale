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
#include <unistd.h>
#include <stdint.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>

#include "digest.h"

using namespace Skytale;

/**
 * @name make - Generates a digest from a message and attach it after the message.
 * @param message_cstr: the message string.
 *
 * This method calculates a message digest and attaches it to the message.
 *
 * @return mmessage+digest string.
 */
std::string MessageDigest::make(const char *message_cstr) {
  CryptoPP::SHA256 hash;
  std::string message(message_cstr);

  std::string message_with_digest;
  
  CryptoPP::StringSink *ss = new CryptoPP::StringSink(message_with_digest);
  CryptoPP::HashFilter *hf = new CryptoPP::HashFilter(hash, ss, true);
  CryptoPP::StringSource st(message, true, hf);

  return message_with_digest;
}

/**
 * @name verify - Verifies a message digest. 
 * @param message_with_digest_cstr: the message+digest string.
 *
 * This method verifies a message digest.
 *
 * @return false: ERROR, true: OK.
 */
bool MessageDigest::verify(const char *message_with_digest_cstr) {
  CryptoPP::SHA256 hash;
  std::string message_with_digest(message_with_digest_cstr);
  std::string clearMessage = message_with_digest.substr(0,message_with_digest.size() - CryptoPP::SHA256::DIGESTSIZE);
  
  std::string digestOfMessage = message_with_digest.substr(clearMessage.size(), message_with_digest.size());
  
  CryptoPP::SecByteBlock digest(CryptoPP::SHA256::DIGESTSIZE);
  CryptoPP::ArraySink *as = new CryptoPP::ArraySink(digest, digest.size());
  CryptoPP::StringSource inDigest(digestOfMessage, true, as);
  CryptoPP::HashVerificationFilter *pVerifier = new CryptoPP::HashVerificationFilter(hash, NULL, CryptoPP::HashVerificationFilter::HASH_AT_BEGIN);

  pVerifier->Put(digest, digest.size());
  
  CryptoPP::StringSource fsVer(clearMessage, true, pVerifier);
  bool result = pVerifier->GetLastResult();
  
  return result;
}	
