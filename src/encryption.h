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
 * Foundation.  See file COPYING.
 * 
 */
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <iostream>
#include <string>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/rsa.h>
#include "common.h"

namespace Skytale {

#define DEFAULT_PRKEY_SIZE 3072

/**
 * @name RandomNumberGenerator - Random Number Generator.
 *
 * This class defines a random generator object. It actually uses the random
 * number generator that is provided by the CryptoPP library.
 */
class RandomNumberGenerator {
 private:
  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption m_random_number_generator;
 public:
  RandomNumberGenerator();
  CryptoPP::RandomNumberGenerator & get();
};

/**
 * @name PublicKey - Public Key object
 *
 * This class defines the Skytale Public Key object. To create a new object call
 * the constructor and pass the public key file or an rsa public key created with
 * the crypto++ library or use the load method to load a public key from a file.
 */
class PublicKey {
 private:
  CryptoPP::RSA::PublicKey m_public_key;
  
 public:
  explicit PublicKey(const CryptoPP::RSA::PublicKey pk);
  PublicKey() {}
  
  void assign(const CryptoPP::RSA::PublicKey pk);
  int32_t load(const char *filename);
  void save(const char *filename);
  CryptoPP::RSA::PublicKey public_key();
  std::string get_key_string();
  std::string get_key_hash(HashFunction hash_func);
  std::string encrypt_message(const char *message, const char *seed = NULL);
  bool verify_message(const char *message, const char *signature); 
};

/**
 * PrivateKey - Private Key object
 *
 * This class defines the Skytale Private Key object. To create a new object call
 * the constructor and pass an rsa private key created with the crypto++ library,
 * or call the load method to load a private key from a file.
 */
class PrivateKey {
 private:
  CryptoPP::RSA::PrivateKey m_private_key;
  RandomNumberGenerator drng;  
 public:
  explicit PrivateKey(const CryptoPP::RSA::PrivateKey sk);
  PrivateKey() {}
  
  void assign(const CryptoPP::RSA::PrivateKey sk);
  int32_t load(const char *filename);
  void save(const char *filename);
  CryptoPP::RSA::PrivateKey private_key();
  std::string get_key_string();
  std::string decrypt_message(const char *message);
  std::string sign_message(const char *message);
};

/**
 * KeyPair - Public Key Pair object
 *
 * This class defines the Skytale Public Key Pair object. To create a new object call
 * the generate method.
 */
class KeyPair {
 private:
  PublicKey *m_public_key;
  PrivateKey *m_private_key;
  
 public:
  KeyPair();
  KeyPair(KeyPair *kp);
  ~KeyPair();

  void generate(int32_t size = DEFAULT_PRKEY_SIZE);
  int32_t load(const char *pk_filename, const char *sk_filename);
  PublicKey *public_key();
  PrivateKey *private_key();
};

}

#endif


