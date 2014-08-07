// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <utility>
#include <libiris/libiris.h>
#include "../src/encryption.h"
#include "../src/authentication.h"

using namespace Skytale;

int validate(const char *id, void *table) {
  return 1;
}


int main(int argc, char *argv[]) {
  char s_addr[INET6_ADDRSTRLEN];
  char data[100];
  
  int status;


  // Server's keypair.
  KeyPair kp;
  kp.generate();
  
  // Server's certificate. We create the certificate manually for testing purposes.
  Certificate cert;
  cert.set_version(1);
  cert.set_serial(1);
  cert.set_time_before(time(0)+100000);
  cert.set_time_after(time(0) - 1000);
  cert.set_signature_algorithm("rsa");
  cert.set_issuer("randomissuer");
  cert.set_subject(kp.public_key()->get_key_hash(SHA256_H));
  cert.set_subject_pk_algorithm("rsa");
  cert.set_subject_pk(kp.public_key()->get_key_string());
  cert.sign("rsa", kp.private_key());
  
  // Prepare the server.
  SecureServer server;
  server.set_certificate(&cert);
  server.set_keypair(&kp);
  
  status = server.start(NULL, "9999", 10);
  if (status) {
    std::cout << "(Server) Error on startup.\n";
    return 1;
  } else {
    std::cout << "(Server) Up and running!\n";
  }
  memset(data, 0, 100);

  void *param;
  
  //
  // Wait for incoming requests 
  //
  while(1) {
    SecureClient *client = new SecureClient;
    status = server.get_client(client);
    if (status ) {
      std::cout << "(Server) get_client error.\n";
      delete client;
      break;
    }
    //
    // A client reached. Try to authenticate it.
    //
    std::cout << "(Server) Client reached.\n";

    status = server.authenticate_client(client, validate, param);
    if (status == 0)
      std::cout << "(Server) Authentication succeeded!\n";
    else
      std::cout << "(Server) Authentication failed!\n";
    
    status = server.receive_secure_data(data, 100, client);
    std::cout << data << std::endl;
    client->detach();
    delete client;
  }
  std::cout << "(Server) Stopping...\n";
  status = server.stop();
  if (status) {
    std::cout << "(Server) Error on stop.\n";
    return 1;
  } else {
    std::cout << "(Server) Stopped!\n";
  }
}
