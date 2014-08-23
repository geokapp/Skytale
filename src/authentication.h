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
#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <ctime>
#include <map>
#include <utility>
#include <libiris/libiris.h>
#include "encryption.h"

namespace Skytale {

#define AUTH_CERT_REQ 0x01
#define AUTH_CERT_REP 0x02
#define AUTH_AUTH_REQ 0x03
#define AUTH_AUTH_REP 0x04

#define AUTH_ALGO_RSA 0x01

#define AUTH_MAX_PACKET_SIZE 16384
#define AUTH_MAX_TIME_SKEW 100

/**
 * @name Certificate - The certificate object.
 *
 * This class defines the certificate object. When creating a new
 * certificate, you should first set all its fields by using the
 * appropriate set methods and then call the sign method to sign
 * it. After that, you can call the pack_to_string method to pack
 * the certificate into a string.
 */
class Certificate {
 private:
  int32_t m_version;
  int32_t m_serial;
  time_t m_time_before;
  time_t m_time_after;
  std::string m_signature_algorithm;
  std::string m_issuer;
  std::string m_subject;
  std::string m_subject_pk_algorithm;
  std::string m_subject_pk;
  std::string m_signature;
  
 public:
  Certificate();
  Certificate(Certificate *cert);
  
  void set_version(const int32_t version);
  void set_serial(const int32_t serial);
  void set_time_before(const time_t before);
  void set_time_after(const time_t after);
  void set_signature_algorithm(const std::string signature_algorithm);
  void set_issuer(const std::string issuer);
  void set_subject(const std::string subject);
  void set_subject_pk_algorithm(const std::string algorithm);
  void set_subject_pk(const std::string pk);
  
  int32_t version();
  int32_t serial();
  time_t time_before();
  time_t time_after();
  std::string signature_algorithm();
  std::string issuer();
  std::string subject();
  std::string subject_pk_algorithm();
  std::string subject_pk();
  std::string signature();
  
  void sign(const std::string algorithm, PrivateKey *prk);
  std::string pack_to_string();
  void unpack_from_string(std::string certificate_str);
  bool is_valid(int32_t (*validate_func)(const char *, void *), void *parameter);
};

/**
 * @name SecureClient - The secure client endpoint object.
 *
 * This class defines the secure client endpoint object. A client side
 * application can use this object to securely exchange data with a server.
 * For example:
 * ------------------------------------
 * SecureClient *client = new SecureClient;
 * ... // Set certificate and keypair.
 * int status = client->attach(server_ip, port);
 * if (!status) {
 *   status = client->authenticate_server(&validate_func, parameter);
 *   if (!status) {
 *     // Authentication succeeded.
 *     status = client->send_secure_data(data, datalen); 
 *   ...
 *   }
 *   client->detach();
 * }
 * delete client;
 * ------------------------------------
 * A server side application can use this object to communicate with a client.
 * For example:
 * ------------------------------------
 * Client *client = new client;
 * int status = server->get_client(client);
 * if (!status) {
 *   status = server->authenticate_client(client, &validate_func, parameter);
 *   if (!status) {
 *     // Authentication succeeded.
 *     server->receive_secure_data(databuf, datalen, client);
 *     ...
 *   }
 *   client->detach();
 * }
 * delete client;
 * ------------------------------------
 */
class SecureClient : public iris::Client {
 private:
  KeyPair *m_keypair;
  Certificate *m_certificate;
  SymmetricKey *m_shared_key;
  std::string m_client_id;
  
 public:
  SecureClient();
  ~SecureClient();

  void set_client_id(std::string id);
  std::string client_id();
  void set_certificate(Certificate *certificate);
  Certificate *certificate();
  void set_keypair(KeyPair *keypair);
  KeyPair *keypair();
  void set_shared_key(SymmetricKey *sk);
  SymmetricKey *shared_key();
  int32_t authenticate_server(int32_t
			      (*validate_func)(const char *, void *),
			      void *parameter);
  int32_t send_secure_data(const void *data, const size_t data_len);
  int32_t receive_secure_data(void *data, const size_t data_len);
};

/**
 * @name SecureServer - The Secure Server endpoint object.
 *
 * This class defines the secure server endpoint object. A server side
 * application can use this object to wait for clients authenticate
 * with them and securely exchange data. For example:
 * ------------------------------------
 * SecureServer *server = new SecureServer;
 * ... // Set certificate and keypair.
 * status = server->start(NULL, 8000, 10);
 * if (!status) {
 *   while(run) {
 *     SecureClient *client = new SecureClient;
 *     status = server->get_client(client);
 *     if (!status) {
 *       status = server->authenticate_client(client, &validate, parameter);
 *       if (!status) {
 *         // Authentication succeeded.
 *         server->receive_secure_data(buf, buf_len, client);
 *         status = client->detach();
 *       }
 *     }
 *     delete client;
 *   }
 *   server->stop();
 * }
 * ------------------------------------
 */
class SecureServer : public iris::Server {
 private:
  KeyPair *m_keypair;
  Certificate *m_certificate;
  std::string m_server_id;

 public:
  SecureServer();
  ~SecureServer();
  void set_server_id(std::string server_id);
  std::string server_id();
  void set_keypair(KeyPair *keypair);
  KeyPair *keypair();
  void set_certificate(Certificate *certificate);
  Certificate *certificate();
  
  int32_t authenticate_client(SecureClient *client, int32_t (*validate_func)(const char*, void*),
			      void *parameter);
  int32_t send_secure_data(const void *data, const size_t data_len,
			   SecureClient *client = NULL);

  int32_t receive_secure_data(void *data, const size_t data_len,
			      SecureClient *client = NULL);
};

}

#endif
