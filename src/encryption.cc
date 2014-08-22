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
#include <cryptopp/aes.h>
#include <cryptopp/crc.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/pssr.h>
#include <cryptopp/osrng.h>
#include <cryptopp/randpool.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>

#include "common.h"
#include "encryption.h"

using namespace Skytale;

/**
 * @name convert_uint_to_string - Convert unsigned int to string.
 * @param in: An unsigned integer.
 *
 * This method converts an unsigned integer into a string.
 *
 * @return String.
 */
std::string convert_uint_to_string(uint32_t in) {
  std::stringstream ss;
  ss << in;
  return ss.str();
}

/**
 * @name RandomNumberGenerator - Constructor.
 *
 * This method initializes a global random generator object. It uses the current
 * time value as a seed.
 */
RandomNumberGenerator::RandomNumberGenerator() {
  std::string seed = convert_uint_to_string(time(NULL));
  
  seed.resize(16);  
  m_random_number_generator.SetKeyWithIV((byte *)seed.data(), 16, (byte *)seed.data());
}

/**
 * @name get - Get a random number.
 *
 * This method returns a random number generator. 
 *
 * @return Random Number Generator.
 */
CryptoPP::RandomNumberGenerator & RandomNumberGenerator::get() {
  return m_random_number_generator;
}

/**
 * @name PublicKey - Constructor
 * @param pk: CryptoPP public key.
 *
 * Initializes the PublicKey object.
 */
PublicKey::PublicKey(const CryptoPP::RSA::PublicKey pk) {
  m_public_key = pk;
}

/**
 * @name load_from_file - Loads a Public Key from a file
 * @param filename: The file name of the public key file.
 *
 * This method loads the key from a public key file.
 *
 * @return 0: success, 1: error
 */
int32_t PublicKey::load_from_file(const char *filename) {
  // First, check if the file exists.
  if (( access(filename, F_OK ) == -1))
    return 1;
  
  CryptoPP::ByteQueue queue;
  CryptoPP::HexDecoder decoder;
  CryptoPP::FileSource file(filename, true);

  // Decode the file and load the key.
  file.TransferTo(decoder);
  decoder.MessageEnd();
  decoder.CopyTo(queue);
  queue.MessageEnd();
  m_public_key.Load(queue);

  return 0;
}

/**
 * @name load_from_string - Loads a Public Key from a string.
 * @param key - The string that contains the key.
 *
 * This method loads the key from a string.
 *
 * @return Void.
 */
void PublicKey::load_from_string(const std::string key) {
  CryptoPP::ByteQueue queue;
  CryptoPP::HexDecoder decoder;
  CryptoPP::StringSource ss(key, true);

  // Decode the string and load the key.
  ss.TransferTo(decoder);
  decoder.MessageEnd();
  decoder.CopyTo(queue);
  queue.MessageEnd();
  m_public_key.Load(queue);
}

/**
 * @name save_to_file - Saves a Public Key to a file
 * @param filename: The file name of the public key file.
 *
 * This method saves the public key to a file.
 *
 * @return Void.
 */
void PublicKey::save_to_file(const char *filename) {
  CryptoPP::ByteQueue queue;
  CryptoPP::HexEncoder encoder;
  CryptoPP::FileSink file(filename);

  // Encode the key to HEX and save to disk.
  m_public_key.Save(queue);
  queue.CopyTo(encoder);
  encoder.MessageEnd();
  encoder.CopyTo(file);
  file.MessageEnd();
}

/**
 * @name assign - Loads a Public Key from an initialized crypto++ RSA key.
 * @param pk: The crypto++ RSA Public Key.
 *
 * This method copies an initialized crypto++ RSA Public Key to the 
 * Skytale Public Key object.
 *
 * @return Void.
 */
void PublicKey::assign(const CryptoPP::RSA::PublicKey pk) {
  m_public_key = pk;
}

/**
 * @name public_key() - Get the public key.
 *
 * Returns the Public key.
 *
 * @return Public Key.
 */
CryptoPP::RSA::PublicKey PublicKey::public_key() {
  return m_public_key;
}

/**
 * @name get_key_string - Get the Public Key string.
 *
 * This method returns the Public Key in a string form.
 *
 * @return A string that contains the Public Key encoded in HEX.
 */
std::string PublicKey::get_key_string() {
  std::string keyStr; 
  CryptoPP::ByteQueue queue;
  CryptoPP::HexEncoder encoder;
  CryptoPP::StringSink ss(keyStr);

  m_public_key.Save(queue);
  queue.CopyTo(encoder);
  encoder.MessageEnd();
  encoder.CopyTo(ss);
  ss.MessageEnd();

  return keyStr;
}

/**
 * @name get_key_hash - Get a hash from the Public Key.
 * @param hash: The hash algorithm.
 *
 * This method returns the hash of a Public Key.
 *
 * @return A string that cotnains the Public Key hash.
 */
std::string PublicKey::get_key_hash(HashFunction hash_func) {
  std::string keyHash;

  CryptoPP::SHA256 hashsha256;
  CryptoPP::SHA384 hashsha384;
  CryptoPP::SHA512 hashsha512;
  CryptoPP::RIPEMD128 hashripemd128;
  CryptoPP::RIPEMD160 hashripemd160;
  CryptoPP::RIPEMD256 hashripemd256;
  CryptoPP::RIPEMD320 hashripemd320;
  CryptoPP::Weak1::MD5 hashmd5;
  CryptoPP::CRC32 hashcrc32;
  CryptoPP::HashFilter *hf;
  
  switch (hash_func) {
    case SHA256_H:
      hf = new CryptoPP::HashFilter(hashsha256);
      break;
    case SHA384_H:
      hf = new CryptoPP::HashFilter(hashsha384);
      break;
    case CRC32_H:
      hf = new CryptoPP::HashFilter(hashcrc32);
      break;
    case RIPEMD128_H:
      hf = new CryptoPP::HashFilter(hashripemd128);
      break;
    case RIPEMD160_H:
      hf = new CryptoPP::HashFilter(hashripemd160);
      break;
    case RIPEMD256_H:
      hf = new CryptoPP::HashFilter(hashripemd256);
      break;
    case RIPEMD320_H:
      hf = new CryptoPP::HashFilter(hashripemd320);
      break;
    case MD5_H:
      hf = new CryptoPP::HashFilter(hashmd5);
      break;
    default:
      hf = new CryptoPP::HashFilter(hashsha512);
      break;
  }
  
  CryptoPP::ByteQueue queue;
  CryptoPP::StringSink *ss = new CryptoPP::StringSink(keyHash);
  CryptoPP::HexEncoder encoder(ss, false);

  queue.CopyTo(*hf);
  hf->MessageEnd();
  hf->TransferTo(encoder);
  
  return keyHash;
}

/**
 * @name encrypt_message - Encrypts a message with the Public Key.
 * @param seed: Seed value.
 * @param message: Plain message.
 *
 * This method encrypts a user provided string with the Public Key. The user
 * can provide an initialized seed. If no seed is provided then the method uses
 * the system clock to generate one.
 *
 * @return A string that cotnains the encrypted message.
 */
std::string PublicKey::encrypt_message(const std::string message,
				       std::string seed) {
  CryptoPP::RSAES_OAEP_SHA_Encryptor pub(m_public_key);
  CryptoPP::RandomPool randPool;
  std::string result;
  std::string seedStr;
  
  if (seed.empty()) {
    seed = convert_uint_to_string(time(NULL));
  }
  randPool.IncorporateEntropy((byte *)seed.c_str(), seed.size());

  int32_t remaining = message.size();
  int32_t step = PLAIN_CHUNK_SIZE;
  int32_t current = 0;
  result.clear();
  while (remaining > 0) {
    // Process the message in chunks.
    std::string chunk_result;
    std::string chunk_message;
    chunk_result.clear();
    chunk_message.clear();
    if (remaining >= step) {
      chunk_message = message.substr(current, step);
      remaining -= step;
    } else {
      chunk_message = message.substr(current, remaining);
      remaining = 0;
    }
    current += step;

    CryptoPP::StringSink *ss = new CryptoPP::StringSink(chunk_result);
    CryptoPP::HexEncoder *he = new CryptoPP::HexEncoder(ss);
    CryptoPP::PK_EncryptorFilter *pkef = new CryptoPP::PK_EncryptorFilter(randPool, pub, he);
    CryptoPP::StringSource(chunk_message, true, pkef);

    result += chunk_result;
  }
  return result;
}





/**
 * @name verify_message - Verify a message signature.
 * @param message: Plain message.
 * @param signature: Signature.
 * 
 * This method verifies a message signature.
 *
 * @return true: OK, false: Error.
 */
bool PublicKey::verify_message(const std::string message,
			       const std::string signature) {
  CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Verifier pub(m_public_key);
  CryptoPP::HexDecoder *hd = new CryptoPP::HexDecoder;
  CryptoPP::StringSource signatureMessage(signature, true, hd);

  if (signatureMessage.MaxRetrievable() != pub.SignatureLength()) 
    return false;

  CryptoPP::SecByteBlock cSignature(pub.SignatureLength());
  signatureMessage.Get(cSignature, cSignature.size());

  CryptoPP::VerifierFilter *verifierFilter = new CryptoPP::VerifierFilter(pub);
  verifierFilter->Put(cSignature, pub.SignatureLength());

  CryptoPP::StringSource s(message, true, verifierFilter);
  bool result = verifierFilter->GetLastResult();

  return result;
}

/**
 * @name PrivateKey - Constructor
 * @param sk: CryptoPP private key.
 *
 * Initializes the PrivateKey object.
 */
PrivateKey::PrivateKey(const CryptoPP::RSA::PrivateKey sk) {
  m_private_key = sk;
}

/**
 * @name load_from_file - Loads a Private Key from a file.
 * @param filename: The file name of the private key file.
 *
 * This method loads the key from a private key file.
 *
 * @return 0: Success, 1: Error.
 */
int32_t PrivateKey::load_from_file(const char *filename) {
  // First, check if the file exists.
  if ((access(filename, F_OK ) == -1))
    return 1;
  
  CryptoPP::ByteQueue queue;
  CryptoPP::HexDecoder decoder;
  CryptoPP::FileSource file(filename, true);

  // Decode the file and load the key.
  file.TransferTo(decoder);
  decoder.MessageEnd();
  decoder.CopyTo(queue);
  queue.MessageEnd();
  m_private_key.Load(queue);

  return 0;
}

/**
 * @name load_from_string - Loads a Private Key from a string.
 * @param key: The string that contains the key.
 *
 * This method loads the key from a string.
 *
 * @return Void.
 */
void PrivateKey::load_from_string(const std::string key) {
  CryptoPP::ByteQueue queue;
  CryptoPP::HexDecoder decoder;
  CryptoPP::StringSource ss(key, true);

  // Decode the file and load the key.
  ss.TransferTo(decoder);
  decoder.MessageEnd();
  decoder.CopyTo(queue);
  queue.MessageEnd();
  m_private_key.Load(queue);
}


/**
 * @name save_to_file - Saves a Private Key to a file.
 * @param filename: The file name of the private key file.
 *
 * This method saves the private key to a file.
 *
 * @return Void.
 */
void PrivateKey::save_to_file(const char *filename) {
  CryptoPP::ByteQueue queue;
  CryptoPP::HexEncoder encoder;
  CryptoPP::FileSink file(filename);

  // Encode the private key to HEX and save it to a file.
  m_private_key.Save(queue);
  queue.CopyTo(encoder);
  encoder.MessageEnd();
  encoder.CopyTo(file);
  file.MessageEnd();
}

/**
 * @name private_key() - Get the private key.
 *
 * Returns the Private key.
 *
 * @return Private Key.
 */
CryptoPP::RSA::PrivateKey PrivateKey::private_key() {
  return m_private_key;
}

/**
 * @name assign - Loads a Private Key from an initialized crypto++ RSA key.
 * @sk: The crypto++ RSA Private Key.
 *
 * This method copies an initialized crypto++ RSA Private Key to the 
 * Skytale Private Key object.
 *
 * @return Void.
 */
void PrivateKey::assign(const CryptoPP::RSA::PrivateKey sk) {
  m_private_key = sk;
}

/**
 * @name get_key_string - Get the Private Key string.
 *
 * This method returns the RSA Private Key in a string form.
 *
 * @return A string that cotnains the Private Key encoded in HEX.
 */
std::string PrivateKey::get_key_string() {
  std::string keyStr; 
  CryptoPP::ByteQueue queue;
  CryptoPP::HexEncoder encoder;
  CryptoPP::StringSink ss(keyStr);

  m_private_key.Save(queue);
  queue.CopyTo(encoder);
  encoder.MessageEnd();
  encoder.CopyTo(ss);
  ss.MessageEnd();
  return keyStr;
}

/**
 * @name decrypt_message - this method decrypts a message.
 * @param message: The encrypted message.
 *
 * This method decrypts a message.
 *
 * @return A string that cotnains the Private Key encoded in HEX.
 */
std::string PrivateKey::decrypt_message(const std::string message) {
  CryptoPP::RSAES_OAEP_SHA_Decryptor priv(m_private_key);
  std::string result;

  int32_t remaining = message.size();
  int32_t step = 2 * CIPHER_CHUNK_SIZE;
  int32_t current = 0;
  result.clear();
  while (remaining > 0) {
    // Process the message in chunks.
    std::string chunk_result;
    std::string chunk_message;
    chunk_result.clear();
    chunk_message.clear();
    if (remaining >= step) {
      chunk_message = message.substr(current, step);
      remaining -= step;
    } else {
      chunk_message = message.substr(current);
      remaining = 0;
    }
    current += step;

    CryptoPP::StringSink *ss = new CryptoPP::StringSink(chunk_result);
    CryptoPP::PK_DecryptorFilter *pkdf = new CryptoPP::PK_DecryptorFilter(m_drng.get(),
									  priv, ss);
    CryptoPP::HexDecoder *hd = new CryptoPP::HexDecoder(pkdf);
    CryptoPP::StringSource(chunk_message, true, hd);

    result += chunk_result;
  }
  return result;
}


/**
 * @name sign_message - Sign a message.
 * @param message: Plain message.
 * 
 * This method signs a messagee.
 *
 * @return Message signature (string)
 */
std::string PrivateKey::sign_message(const std::string message) {
  std::string signature;
  
  CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Signer priv(m_private_key);
  CryptoPP::StringSink *ss = new CryptoPP::StringSink(signature);
  CryptoPP::HexEncoder *he = new CryptoPP::HexEncoder(ss);
  CryptoPP::SignerFilter *sf = new CryptoPP::SignerFilter(m_drng.get(), priv, he);
  CryptoPP::StringSource signature_source(message, true, sf);

  return signature;
}

/** @name KeyPair - Constructor.
 *
 * The default constructor.
 */
KeyPair::KeyPair() {
  m_public_key = NULL;
  m_private_key = NULL;
}

/**
 * @name KeyPair - Copy Constructor.
 *
 * The default constructor.
 */
KeyPair::KeyPair(KeyPair *kp) {
  m_public_key = new PublicKey(kp->public_key()->public_key());
  m_private_key = new PrivateKey(kp->private_key()->private_key());
}

/**
 * @name KeyPair - Destructor.
 *
 * The default destructor.
 */
KeyPair::~KeyPair() {
  if (m_public_key)
    delete m_public_key;
  
  if (m_private_key) 
    delete m_private_key;

  m_public_key = NULL;
  m_private_key = NULL;
}


/**
 * @name generate - Generate a key pair.
 * @param size: The size. If no size is specified The default is 3072.
 *
 * This method generates a Skytale Key Pair object.
 *
 * @return Void.
 */
void KeyPair::generate(int32_t size) {
  CryptoPP::RSA::PrivateKey sk;
  CryptoPP::RSA::PublicKey pk;
  CryptoPP::AutoSeededRandomPool rnd;
  
  sk.GenerateRandomWithKeySize(rnd, size);
  pk.AssignFrom(sk);
  m_public_key = new PublicKey(pk);
  m_private_key = new PrivateKey(sk);
}

/**
 * @name load - Load a key pair.
 * @param pk_filename: The filename of the public key file.
 * @param sk_filename: The filename of the private key file.
 *
 * Loads a key pair from disk.
 *
 * @return 0: success, 1: error.
 */
int32_t KeyPair::load(const char *pk_filename, const char *sk_filename) {
  m_public_key = new PublicKey();
  m_private_key = new PrivateKey();
  int32_t result = m_public_key->load_from_file(pk_filename);
  if (!result)
    result = m_private_key->load_from_file(sk_filename);
  return result;
}

/**
 * @name set_public_key - Set public key.
 * @param pk: A poitner to a public key.
 *
 * Sets the public key.
 *
 * @return Void.
 */
void KeyPair::set_public_key(PublicKey *pk) {
  m_public_key = pk;
}

/**
 * @name set_private_key - Set private key.
 * @param uk: A poitner to a private key.
 *
 * Sets the private key.
 *
 * @return Void.
 */
void KeyPair::set_private_key(PrivateKey *uk) {
  m_private_key = uk;
}

/**
 * @name public_key - Return the Public Key.
 *
 * This method returns a Skytale Public Key object.
 *
 * @return The Skytale Public Key object or NULL.
 */
PublicKey *KeyPair::public_key() {
  return m_public_key;
}

/**
 * @name private_key - Return the Private Key.
 *
 * This method returns a Skytale Private Key object.
 *
 * @return A Skytale Private Key object or NULL.
 */
PrivateKey *KeyPair::private_key() {
  return m_private_key;
}

/**
 * @name SymmetricKey - Constructor.
 *
 * The default constructor.
 */
SymmetricKey::SymmetricKey() {
  m_key = NULL;
  m_iv = NULL;
}

/**
 * @name SymmetricKey - Copy constructor.
 *
 * The Copy constructor.
 */
SymmetricKey::SymmetricKey(SymmetricKey *sk) {
  if (sk) {
    m_key = new byte[sk->key_size()];
    memcpy(m_key, sk->key(), sk->key_size());
    m_iv = new byte[CryptoPP::AES::DEFAULT_KEYLENGTH];
    memcpy(m_iv, sk->iv(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    m_key_size = sk->key_size();
  }
}

  
/**
 * @name ~SymmetricKey - Destructor.
 *
 * The default destructor.
 */
SymmetricKey::~SymmetricKey() {
  if (m_key)
    delete m_key;
  if (m_iv)
    delete m_iv;
}

/**
 * @name generate - Generate symmetric key and IV.
 * @param size: The key size in Bytes. It can be either 16, 24, or 32. The
 *              default is 16.
 *
 * This method generates a random symmetric key and a random IV.
 *
 * @return Void.
 */
void SymmetricKey::generate(uint16_t size) {
  // Check size.
  if (size != 16 && size != 24 && size != 32)
    return;
  
  // Generate a random key.
  m_key = new byte[size];
  m_rnd.GenerateBlock(m_key, size);
  m_key_size = size;
  
  // Generate a random IV.
  m_iv = new byte[CryptoPP::AES::BLOCKSIZE];
  m_rnd.GenerateBlock(m_iv, CryptoPP::AES::BLOCKSIZE);
}

/**
 * @name set_key - Set the key.
 * @param key: An AES key encoded in Hex format.
 * @param size: The size of the key in Bytes. It can be either 16, 24, or 32. The
 *              default is 16.
 *
 * This method sets the key.
 * @return Void.
 */
void SymmetricKey::set_key(std::string key, uint16_t size) {
  if (!m_key) {
    m_key = new byte[size];
    std::string key_str;
    key_str.clear();
    CryptoPP::StringSource ssk(key, true /*pump all*/,
			       new CryptoPP::HexDecoder(
				   new CryptoPP::StringSink(key_str)));
    memcpy(m_key, key_str.data(), size);
    m_key_size = size;
  }
}

/**
 * @name set_iv - Set IV.
 * @param iv: The IV encoded in Hex format.
 *
 * This method sets the IV.
 *
 * @return Void.
 */
void SymmetricKey::set_iv(std::string iv) {
  if (!m_iv) {
    m_iv = new byte[CryptoPP::AES::BLOCKSIZE];
    std::string iv_str;
    iv_str.clear();
    CryptoPP::StringSource ssi(iv, true /*pump all*/,
			       new CryptoPP::HexDecoder(
				   new CryptoPP::StringSink(iv_str)));

    memcpy(m_iv, iv_str.data(), CryptoPP::AES::BLOCKSIZE);
  }
}

/**
 * @name set_key_size - Set key size.
 * @param size: The key size. It can be either 16, 24, or 32. The default is
 *              16.
 *
 * Set the key size.
 *
 * @return Void.
 */
void SymmetricKey::set_key_size(uint16_t size) {
  // Check size.
  if (size != 16 && size != 24 && size != 32)
    return;
  
  m_key_size = size;
}

/**
 * @name key - Return the key.
 *
 * Returns the key.
 *
 * @return A byte array that contains the key.
 */
byte *SymmetricKey::key() {
  return m_key;
}

/**
 * @name iv - Return the iv.
 *
 * Returns the iv.
 *
 * @return A byte array that contains the iv.
 */
byte *SymmetricKey::iv() {
  return m_iv;
}

/**
 * @name key_size - Return the size of the key.
 *
 * Returns the key size.
 *
 * @return The key size.
 */
int32_t SymmetricKey::key_size() {
  return m_key_size;
}

/**
 * @name get_key_string - Return the key.
 *
 * Returns a Hex encoded string that contains the key.
 *
 * @return Key string.
 */
std::string SymmetricKey::get_key_string() {
  std::string encoded;
  CryptoPP::StringSource ss(m_key, m_key_size, true,
			    new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(encoded)));
  
  return encoded;
}

/**
 * @name get_iv_string - Return the iv.
 *
 * Returns a Hex encoded string that contains the iv.
 *
 * @return iv string.
 */
std::string SymmetricKey::get_iv_string() {
  std::string encoded;
  CryptoPP::StringSource ss(m_iv, CryptoPP::AES::DEFAULT_KEYLENGTH, true,
			    new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(encoded)));
  
  return encoded;
}

/**
 * @name encrypt - Encrypt a message.
 * @param plain_message: The plain message.
 *
 * This method encrypts a message by using the CBC mode of AES.
 *
 * @return The ciphertext.
 */
std::string SymmetricKey::encrypt(const std::string plain_message) {
  if (!m_key || !m_iv)
    return "";

  int32_t message_len = plain_message.size();
  std::string plain_message_str(plain_message);
  std::string result;
  result.clear();
  
  // StreamTransformationFilter adds padding.
  CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
  encryptor.SetKeyWithIV(m_key, m_key_size, m_iv);

  CryptoPP::StringSource s(plain_message, true,
			   new CryptoPP::StreamTransformationFilter(encryptor,
						   new CryptoPP::StringSink(result)));

  // Encode the ciphertext into Hex Format.
  std::string encoded;
  encoded.clear();
  CryptoPP::StringSource ss(result, true,
			    new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(encoded)));
  return encoded;
}

/**
 * @name decrypt - Decrypt a message.
 * @param encrypted_message: The ciphertext.
 *
 * This method decrypts a message by using the CBC mode of AES.
 *
 * @return The plain text.
 */
std::string SymmetricKey::decrypt(std::string encrypted_message) {
  if (!m_key || !m_iv)
    return "";

  // Decode the ciphertext from Hex Format.
  std::string decoded;
  decoded.clear();
  CryptoPP::StringSource ss_decode(encrypted_message, true,
			    new CryptoPP::HexDecoder(
				new CryptoPP::StringSink(decoded)));

  
  int32_t message_len = decoded.size();
  
  std::string result;
  result.clear();
  CryptoPP::StringSink *ss_decrypt = new CryptoPP::StringSink(result);
  CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
  decryptor.SetKeyWithIV(m_key, m_key_size, m_iv);

  // StreamTransformationFilter removes padding.
  CryptoPP::StringSource ss_transform(decoded, true,
			   new CryptoPP::StreamTransformationFilter(decryptor,
						new CryptoPP::StringSink(result)));

  return result;
}
