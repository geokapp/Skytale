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
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdint.h>
#include <iostream>
#include <string>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include "common.h"

namespace Skytale {

#define DEFAULT_PRKEY_SIZE 3076
#define PLAIN_CHUNK_SIZE 343
#define CIPHER_CHUNK_SIZE 385
#define DEFAULT_AES_KEY_LENGTH CryptoPP::AES::DEFAULT_KEYLENGTH

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
  int32_t load_from_file(const char *filename);
  void save_to_file(const char *filename);
  void load_from_string(const std::string key);
  CryptoPP::RSA::PublicKey public_key();
  std::string get_key_string();
  std::string get_key_hash(HashFunction hash_func);
  std::string encrypt_message(const std::string message, std::string seed = "");
  bool verify_message(const std::string message, const std::string signature); 
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
  RandomNumberGenerator m_drng;  
 public:
  explicit PrivateKey(const CryptoPP::RSA::PrivateKey sk);
  PrivateKey() {}
  
  void assign(const CryptoPP::RSA::PrivateKey sk);
  int32_t load_from_file(const char *filename);
  void load_from_string(const std::string key);
  void save_to_file(const char *filename);
  CryptoPP::RSA::PrivateKey private_key();
  std::string get_key_string();
  std::string decrypt_message(const std::string message);
  std::string sign_message(const std::string message);
};

/**
 * KeyPair - Public Key Pair object
 *
 * This class defines the Skytale Public Key Pair object. To create a new object
 * call the generate method.
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
  void set_public_key(PublicKey *pk);
  void set_private_key(PrivateKey *uk);
  PublicKey *public_key();
  PrivateKey *private_key();
};

/**
 * SymmetricKey - Symmetric Key object
 *
 * This class defines the Skytale Symmetric Key object. To create a new object call
 * the constructor. To generate a new random key and iv call the generate method.
 * To load an existing key and IV use the set_key and set_iv methods.
 */
class SymmetricKey {
 private:
  byte *m_key;
  byte *m_iv;
  uint16_t m_key_size;
  CryptoPP::AutoSeededRandomPool m_rnd;
  
 public:
  SymmetricKey();
  SymmetricKey(SymmetricKey *sk);
  
  ~SymmetricKey();
  void generate(uint16_t size = CryptoPP::AES::DEFAULT_KEYLENGTH);
  byte *key();
  byte *iv();
  int32_t key_size();
  std::string get_key_string();
  std::string get_iv_string();
  void set_key(std::string key, uint16_t size =
	       CryptoPP::AES::DEFAULT_KEYLENGTH);
  void set_iv(std::string iv);
  void set_key_size(uint16_t size);
  std::string  encrypt(const std::string plain_message);
  std::string decrypt(const std::string encrypted_message);
};

}

#endif


