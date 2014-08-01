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

  std::cout << "1. Testing message digests.\n\n";

  //
  // Test the MessageDigest class.
  //
  MessageDigest messageDigest;

  std::string mhash = messageDigest.make(message.c_str());

  if (messageDigest.verify(mhash.c_str()))
    std::cout << "Result OK\n";

  else
    std::cout << "Result ERROR\n";

  //
  // Test Public key encryption.
  //
  std::cout << "\n2. Testing Key Pairs.\n\n";
  
  KeyPair pair;
  pair.generate();
  
  std::cout << "--- start of public key -- \n";
  std::cout << pair.public_key()->get_key_string();
  std::cout << "\n--- end of public key ---\n\n";

  std::cout << "--- start of private key -- \n";
  std::cout << pair.private_key()->get_key_string();
  std::cout << "\n--- end of private key ---\n\n";
  
  std::cout <<"hash: " << pair.public_key()->get_key_hash(SHA256_H) << "\n";


  std::cout <<"------------------------------\n";
  std::string plain = "Hello There! I am a short message. faskldfs fnsdk nsdsdsdffsd sfsdkfs dfsfsdlfjwefwe fwefehfei fweofh\n \0 ";
  std::cout <<"Plain Message: " << plain << std::endl;
  std::cout <<"Plain message size: " << plain.size() << std::endl;
  std::cout <<"------------------------------\n";
  
  std::string cipher = pair.public_key()->encrypt_message(plain);

  std::cout <<"------------------------------\n";
  std::cout <<"Ciphertext: " << cipher << std::endl;
  std::cout <<"Ciphertext size: " << cipher.size() << std::endl;
  std::cout <<"------------------------------\n";

  std::string result = pair.private_key()->decrypt_message(cipher);
  
  std::cout <<"------------------------------\n";
  std::cout <<"decrypted text: " << result << std::endl;
  std::cout <<"decrytped text size: " << result.size() << std::endl;
  std::cout <<"------------------------------\n";
  
  if (plain == result)
    std::cout << "Result OK\n";
  else
    std::cout << "Result Error\n";

  //
  // Test symmetric encryption.
  //

  std::cout <<"\n3. Testing symmetric key encryption.\n\n";

  std::cout <<"------------------------------\n";
  std::cout <<"Plain Message: " << plain << std::endl;
  std::cout <<"Plain message size: " << plain.size() << std::endl;
  std::cout <<"------------------------------\n";

  SymmetricKey aes_key;
  aes_key.generate();
  
  cipher = aes_key.encrypt(plain);
  std::cout <<"------------------------------\n";
  std::cout <<"Ciphertext: " << cipher << std::endl;
  std::cout <<"Ciphertext size: " << cipher.size() << std::endl;
  std::cout <<"------------------------------\n";

  result = aes_key.decrypt(cipher);
  std::cout <<"------------------------------\n";
  std::cout <<"decrypted text: " << result << std::endl;
  std::cout <<"decrytped text size: " << result.size() << std::endl;
  std::cout <<"------------------------------\n";
  
  if (plain == result)
    std::cout << "Result OK\n";
  else
    std::cout << "Result Error\n";
  
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
