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
#include <cryptopp/crc.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include "digest.h"

using namespace Skytale;

/**
 * @name make - Generates a digest from a message and attach it after the message.
 * @param message_cstr: the message string.
 *
 * This method calculates a message digest and attaches it to the message.
 *
 * @return message+digest string.
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

/**
 * @name hash - Generates a hash from a message.
 * @param message_cstr: the message string.
 *
 * This method calculates the cryptographic hash of a message.
 *
 * @return message hash.
 */
std::string MessageDigest::hash(const HashFunction hash_func, const char *message_cstr) {
  std::string message(message_cstr); 
  std::string result;
  CryptoPP::SHA256 hashsha256;
  CryptoPP::SHA384 hashsha384;
  CryptoPP::SHA512 hashsha512;
  CryptoPP::RIPEMD128 hashripemd128;
  CryptoPP::RIPEMD160 hashripemd160;
  CryptoPP::RIPEMD256 hashripemd256;
  CryptoPP::RIPEMD320 hashripemd320;
  CryptoPP::Weak1::MD5 hashmd5;
  CryptoPP::CRC32 hashcrc32;
  CryptoPP::StringSink *ss = new CryptoPP::StringSink(result);
  CryptoPP::HexEncoder *he = new CryptoPP::HexEncoder(ss);
  CryptoPP::HashFilter *hf;
  
  switch (hash_func) {
    case SHA256_H:
      hf = new CryptoPP::HashFilter(hashsha256, he);
      break;
    case SHA384_H:
      hf = new CryptoPP::HashFilter(hashsha384, he);
      break;
    case CRC32_H:
      hf = new CryptoPP::HashFilter(hashcrc32, he);
      break;
    case RIPEMD128_H:
      hf = new CryptoPP::HashFilter(hashripemd128, he);
      break;
    case RIPEMD160_H:
      hf = new CryptoPP::HashFilter(hashripemd160, he);
      break;
    case RIPEMD256_H:
      hf = new CryptoPP::HashFilter(hashripemd256, he);
      break;
    case RIPEMD320_H:
      hf = new CryptoPP::HashFilter(hashripemd320, he);
      break;
    case MD5_H:
      hf = new CryptoPP::HashFilter(hashmd5, he);
      break;
    default:
      hf = new CryptoPP::HashFilter(hashsha512, he);
      break;
  }
  CryptoPP::StringSource st(message, true, hf);
  return result;
}
