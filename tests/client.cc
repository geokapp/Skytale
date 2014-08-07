// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <utility>
#include <iostream>
#include <libiris/libiris.h>
#include "../src/encryption.h"
#include "../src/authentication.h"

using namespace Skytale;

int validate(const char *id, void *table) {
  return 1;
}


int main(int argc, char *argv[]) {
  
  char s_addr[INET6_ADDRSTRLEN];
  char data[20] = "Hello World!\0";
  
  int status; 
  
  // Client's keypair.
  KeyPair kp;
  kp.generate();
  
  // Client's certificate. We create the certificate manually for testing purposes.
  Certificate cert;
  cert.set_version(1);
  cert.set_serial(1);
  cert.set_time_before(time(0)+100000);
  cert.set_time_after(time(0) - 1000);
  cert.set_signature_algorithm("rsa");
  cert.set_issuer("randomissuer");
  std::string myid = kp.public_key()->get_key_hash(SHA256_H);
  cert.set_subject(myid);
  cert.set_subject_pk_algorithm("rsa");
  cert.set_subject_pk(kp.public_key()->get_key_string());
  cert.sign("rsa", kp.private_key());

  char *param = new char[10];
  memcpy(param, "hi", 10);
  void *param2;
  //param2 = static_cast<void *>(param);
  
  if (cert.is_valid(&validate, param2))
    std::cout << "valid\n";
      
  // Prepare the client.
  SecureClient client;
  client.set_client_id(kp.public_key()->get_key_hash(SHA256_H));
  client.set_certificate(&cert);
  client.set_keypair(&kp);
  
  // Try to connect to the server.
  status = client.attach("localhost", "9999");    
  if (status) {
    std::cout << "(Client) Error connecting with the server.\n";
  } else {
    std::cout <<"(Client) Attached!\n";

    // Try to authenticate with the server.
    status = client.authenticate_server(validate, param);
    if (status == 0)
      std::cout << "(Client) Authentication succeeded!\n";
    else
      std::cout << "(Client) Authentication failed!\n";

    status = client.send_secure_data(data, strlen(data));
  }
  std::cout << "(Client) Detaching...\n";
  client.detach();
 
  return 0;
}
