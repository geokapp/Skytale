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

#include "../src/common.h"
#include "../src/digest.h"
#include "../src/encryption.h"

using namespace Skytale;

int main() {
  std::string message = "Hello World!\n423h«&*(^!*(#R*(!9H8Ytudg!@ui#gdgd@uigdhqi@gbed@(d@gdcqugdciq";

  // Test the MessageDigest class.
  MessageDigest messageDigest;

  std::string mhash = messageDigest.make(message.c_str());

  if (messageDigest.verify(mhash.c_str()))
    std::cout << "OK!\n";

  else
    std::cout << "ERROR!\n";

  KeyPair pair;
  pair.generate();
  
  std::cout << "--- start of public key -- \n";
  std::cout << pair.public_key()->get_key_string();
  std::cout << "\n--- end of public key ---\n\n";

  std::cout << "--- start of private key -- \n";
  std::cout << pair.private_key()->get_key_string();
  std::cout << "\n--- end of private key ---\n\n";


  std::cout <<"hash: " << pair.public_key()->get_key_hash(SHA256_H) << "\n";
  /*

  DPublicKey pk = pair.getPublicKey();

  DPrivateKey sk = pair.getPrivateKey();

  string message2 = "Hello World!";

  string encrypted = pk.encryptString("dadajo", message2.c_str());

  cout << "Encryption works! \n";


  string decrypted = sk.decryptString(encrypted.c_str());


  cout << "Decryptio works! \n";


  cout << "Message: " << message2 << "\n------\n";

  cout << "Encrypted : " << encrypted << "\n------\n";

  cout << "Decrypted : " << decrypted << "\n";

  */
  return 0;
}
