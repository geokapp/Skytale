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
#include <map>
#include <utility>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include "authentication.h"
#include "encoder.h"
#include "encryption.h"


using namespace Skytale;

/**
 * @name auth_operation - Get operation string identifier.
 * @param op: The operation.
 *
 * This function returns a string identifier that represents an operation.
 *
 * @return String identifier.
 */
const std::string auth_operation(int32_t op) {
  switch (op) {
    case AUTH_CERT_REQ:
      return "CERT_REQ";
    case AUTH_CERT_REP:
      return "CERT_REP";
    case AUTH_AUTH_REQ:
      return "AUTH_REQ";
    case AUTH_AUTH_REP:
      return "AUTH_REP";
    default:
      return "";
  }
}

/**
 * @name auth_algorithm - Get algorithm string identifier.
 * @param algo: The algorith.
 *
 * This function returns a string identifier that represents an algorithm.
 *
 * @return String identifier.
 */
const std::string auth_algorithm(int32_t algo) {
  switch (algo) {
    case AUTH_ALGO_RSA:
      return "rsa";
    default:
      return "";
  }
}

/**
 * @name Certificate - Constructor.
 *
 * This is the default constructor.
 */
Certificate::Certificate() {
  m_version = 0;
  m_serial = 0;
  m_time_before = 0;
  m_time_after = 0;
  m_signature_algorithm.clear();
  m_issuer.clear();
  m_subject.clear();
  m_subject_pk_algorithm.clear();
  m_subject_pk.clear();
  m_signature.clear();
}

/**
 * @name Certificate - Copy constructor.
 *
 * This is the default copy constructor.
 */
Certificate::Certificate(Certificate *cert) {
  m_version = cert->version();
  m_serial = cert->serial();
  m_time_before = cert->time_before();
  m_time_after = cert->time_after();
  m_signature_algorithm = cert->signature_algorithm();
  m_issuer = cert->issuer();
  m_subject = cert->subject();
  m_subject_pk_algorithm = cert->subject_pk_algorithm();
  m_subject_pk = cert->subject_pk();
  m_signature = cert->signature();
}

/**
 * @name set_version - Set version.
 * @param version: The version number.
 *
 * Sets the certificate version.
 *
 * @return Void.
 */
void Certificate::set_version(const int32_t version) {
  m_version = version;
}

/**
 * @name set_serial - Set serial number.
 * @param serial: The serial number.
 *
 * Sets the certificate serial number.
 *
 * @return Void.
 */
void Certificate::set_serial(const int32_t serial) {
  m_serial = serial;
}

/**
 * @name set_time_before - Set before time limit.
 * @param before: The before time limit.
 *
 * Sets the certificate before time limit.
 *
 * @return Void.
 */
void Certificate::set_time_before(const time_t before) {
  m_time_before = before;
}

/**
 * @name set_time_after - Set after time limit.
 * @param after: The after time limit.
 *
 * Sets the certificate after time limit.
 *
 * @return Void.
 */
void Certificate::set_time_after(const time_t after) {
  m_time_after = after;
}

/**
 * @name set_signature - Set signature algorithm.
 * @param signature: The signature algorithm identifier.
 *
 * Sets the certificate signature algorithm identifier.
 *
 * @return Void.
 */
void Certificate::set_signature_algorithm(const std::string signature_algorithm) {
  m_signature_algorithm = signature_algorithm;
}

/**
 * @name set_issuer - Set issuer ID.
 * @param issuer: The certificate issuer identifier.
 *
 * Sets the certificate issuer identifier.
 *
 * @return Void.
 */
void Certificate::set_issuer(const std::string issuer) {
  m_issuer = issuer;
}

/**
 * @name set_subject - Set subject.
 * @param subject: The certificate subject.
 *
 * Sets the certificate subject.
 *
 * @return Void.
 */
void Certificate::set_subject(const std::string subject) {
  m_subject = subject;
}

/**
 * @name set_subject_pk_algorithm - Set subject algorithm.
 * @param subject_pk_algorithm: The algoritm identifier of the subject.
 *
 * Sets the certificate subject algorithm identifier.
 *
 * @return Void.
 */
void Certificate::set_subject_pk_algorithm(const std::string subject_pk_algorithm) {
  m_subject_pk_algorithm = subject_pk_algorithm;
}

/**
 * @name set_subject_pk - Set subject public key.
 * @param subject_pk: The subject's public key.
 *
 * Sets the subject's public key.
 *
 * @return Void.
 */
void Certificate::set_subject_pk(const std::string subject_pk) {
  m_subject_pk = subject_pk;
}

/**
 * @name version - Get Version.
 *
 * Get the certificate version.
 *
 * @return The version number.
 */
int32_t Certificate::version() {
  return m_version;
}

/**
 * @name serial - Get Serial.
 *
 * Get the certificate serial number.
 *
 * @return The certificate serial number.
 */
int32_t Certificate::serial() {
  return m_serial;
}

/**
 * @name time_before - Get the before time limit.
 *
 * Get the certificate before time limit.
 *
 * @return The certificate before time limit.
 */
time_t Certificate::time_before() {
  return m_time_before;
}

/**
 * @name time_after - Get the after time limit.
 *
 * Get the certificate after time limit.
 *
 * @return The certificate after time limit.
 */
time_t Certificate::time_after() {
  return m_time_after;
}

/**
 * @name signature_algorithm - Get the signature algorithm.
 *
 * Get the identifier of the algorithm used to sign the certificate.
 *
 * @return The algorithm identifier.
 */
std::string Certificate::signature_algorithm() {
  return m_signature_algorithm;
}

/**
 * @name issuer - Get the issuer ID.
 *
 * Get the identifier of the certificate issuer.
 *
 * @return The issuer identifier.
 */
std::string Certificate::issuer() {
  return m_issuer;
}

/**
 * @name subject - Get the subject ID.
 *
 * Get the identifier of the certificate subject.
 *
 * @return The subject identifier.
 */
std::string Certificate::subject() {
  return m_subject;
}

/**
 * @name subject_pk_algorithm - Get the public key algorithm.
 *
 * Get the identifier of the algorithm used for the public key of the subject.
 *
 * @return The algorithm identifier.
 */
std::string Certificate::subject_pk_algorithm() {
  return m_subject_pk_algorithm;
}

/**
 * @name subject_pk - Get the subject's public key.
 *
 * Get the subject's public key.
 *
 * @return The public key in string format.
 */
std::string Certificate::subject_pk() {
  return m_subject_pk;
}

/**
 * @name signature - Get the certificate's signature.
 *
 * Get the certificate's signature.
 *
 * @return The signature string.
 */
std::string Certificate::signature() {
  return m_signature;
}

/**
 * @name sign - Sign the certificate.
 * @param prk: A pointer to the private key taht will be used to sign the
 *             certificate.
 * @param algorithm: The algorithm used to generate the private key.
 *
 * This function signs the certificate contents.
 *
 * @return Void.
 */
void Certificate::sign(const std::string algorithm, PrivateKey *prk) {
  Encoder enc;

  enc.put(m_version);
  enc.put(m_serial);
  enc.put(m_time_before);
  enc.put(m_time_after);
  enc.put(m_signature);
  enc.put(m_issuer);
  enc.put(m_subject);
  enc.put(m_subject_pk_algorithm);
  enc.put(m_subject_pk);

  if (algorithm == auth_algorithm(AUTH_ALGO_RSA && prk)) {
    std::string pack = enc.get();  
    m_signature = prk->sign_message(pack);
  } else {
    std::cerr << "Skytale::Certificate::sign: Algorithm " << algorithm << " not supported.\n";
  }
  
}

/**
 * @name pack_to_string - Pack certificate to string.
 *
 * This function uses the encoder object to generate a string that contains
 * all the certificate fields.
 *
 * @return A string that contains the certificate.
 */
std::string Certificate::pack_to_string() {
  Encoder enc;

  enc.put(m_version);
  enc.put(m_serial);
  enc.put(m_time_before);
  enc.put(m_time_after);
  enc.put(m_signature_algorithm);
  enc.put(m_issuer);
  enc.put(m_subject);
  enc.put(m_subject_pk_algorithm);
  enc.put(m_subject_pk);
  enc.put(m_signature);
  
  return enc.get();
}

/**
 * @name unpack_from_string - Unpack a certificate from a string.
 * @param certificate_str: The string that contains the certificate fields encoded.
 *
 * This function decodes a string that contains the certificate fields.
 *
 * @return Void.
 */
void Certificate::unpack_from_string(std::string certificate_str) {
  Decoder dec(certificate_str);

  m_version = dec.get<int32_t>();
  m_serial = dec.get<int32_t>();
  m_time_before = dec.get<time_t>();
  m_time_after = dec.get<time_t>();
  m_signature_algorithm = dec.get<std::string>();
  m_issuer = dec.get<std::string>();
  m_subject = dec.get<std::string>();
  m_subject_pk_algorithm = dec.get<std::string>();
  m_subject_pk = dec.get<std::string>();
  m_signature = dec.get<std::string>();
}

/**
 * @name save_to_file - Save certificate to file.
 * @param filename: The filename.
 *
 * This method packs the certificate and then stores it to a
 * file.
 *
 * @return 0 on success, 1 on error..
 */
void Certificate::save_to_file(const std::string filename) {
  std::string pack = this->pack_to_string();
  CryptoPP::HexEncoder encoder;
  CryptoPP::StringSource ss(pack, true);
  CryptoPP::FileSink file(filename.c_str());

  ss.CopyTo(encoder);
  encoder.MessageEnd();
  encoder.CopyTo(file);
  file.MessageEnd();
}

/**
 * @name load_from_file - Load certificate from file.
 * @param filename: The filename.
 *
 * This method loads the certificate from a file.
 *
 * @return 0 on success, 1 on error..
 */
int32_t Certificate::load_from_file(const std::string filename) {
  // Check file status.
  if (access(filename.c_str(), F_OK) == -1)
    return 1;

  std::string cert;
  CryptoPP::HexDecoder decoder;
  CryptoPP::FileSource file(filename.c_str(), true);
  CryptoPP::StringSink ss(cert);

  file.TransferTo(decoder);
  decoder.MessageEnd();
  decoder.CopyTo(ss);
  ss.MessageEnd();

  this->unpack_from_string(cert);

  return 0;
}


/**
 * @name is_valid - Check certificate validity.
 * @param validate_func: A pointer to user provided validation function.
 * @param parameter: Pointer to a data structure used as a parameter for
 *         the user defined validate_func function.
 *
 * This function first checks the certificate time limits against current
 * time. Then, it uses a uer provided function in order to verify that the
 * certificate has been signed by a a trusted CA or a chain of CA's. This
 * function must take as an argument a string that contains the certificate
 * contents. This string should be generated by using the certificate's
 * pack_to_string method. The function can also take a second parameter
 * which is a pointer to a user-defined data structure. The user must
 * properly cast the void type to the proper data type. For example if the
 * data type is TYPE then the user must do the following:
 * TYPE *p = static_cast<TYPE*>(parameter);
 * If the validate_func argument is NULL, the function assumes that the
 * certificate is not valid.
 *
 * @return true: The certificate is valid, false: The certificate is invalid.
 */
bool Certificate::is_valid(int32_t (*validate_func)(const char *, void *),
			   void *parameter) {
  // First check the time.
  time_t now = time(0);
  if (difftime(now, m_time_after) < 0)
    return false;
  else if (difftime(now, m_time_before) > 0)
    return false;

  // Now validate the certificate with the issuer.
  if (validate_func)
    return (bool)(*validate_func)(this->pack_to_string().c_str(), parameter);
  else
    return false;
}

/**
 * @name SecureClient - Constructor.
 *
 * The default constructor.
 */
SecureClient::SecureClient() {
  m_keypair = NULL;
  m_certificate = NULL;
  m_shared_key = NULL;
  m_client_id.clear();
}

/**
 * @name SecureClient - Destructor.
 *
 * The default destructor.
 */
SecureClient::~SecureClient() {
  if (m_keypair)
    delete m_keypair;
  m_keypair = NULL;

  if (m_certificate)
    delete m_certificate;
  m_certificate = NULL;

  if (m_shared_key)
    delete m_shared_key;
  m_shared_key = NULL;
}

/**
 * @name set_client_id - Set Client ID.
 * @param id: ID derived from client's public key.
 *
 * Sets the ID of the client.
 *
 * @return Void.
 */
void SecureClient::set_client_id(std::string id) {
  m_client_id = id;
}

/**
 * @name client_id - Get Client ID.
 *
 * Get the ID of the client.
 *
 * @return ID in string form.
 */
std::string SecureClient::client_id() {
  return m_client_id;
}

/**
 * @name set_certificate - Set client certificate.
 * @param certificate: client certificate.
 *
 * Sets the client certificate.
 *
 * @return Void.
 */
void SecureClient::set_certificate(Certificate *certificate) {
  m_certificate = new Certificate(certificate);
}

/**
 * @name certificate - Return the certificate.
 *
 * Returns the client's certificate.
 *
 * @return Pointer to a certificate object.
 */
Certificate *SecureClient::certificate() {
  return m_certificate;
}

/**
 * @name set_keypair - Set client keypair.
 * @param keypair: client's keypair.
 *
 * Sets the keypair.
 *
 * @return Void.
 */
void SecureClient::set_keypair(KeyPair *keypair) {
  m_keypair = new KeyPair(keypair);
}

/**
 * @name keypair - Return the keypair.
 *
 * Returns the client's keypair.
 *
 * @return Pointer to a keypair object.
 */
KeyPair *SecureClient::keypair() {
  return m_keypair;
}

/**
 * @name set_shared_key - Set client-server shared key.
 * @param sk: Shared symmetric key.
 *
 * Sets the shared symmetric key for the session.
 *
 * @return Void.
 */
void SecureClient::set_shared_key(SymmetricKey *sk) {
  if (!m_shared_key)
    m_shared_key = new SymmetricKey(sk);
}

/**
 * @name shared_key - Return the shared symmetric key.
 *
 * Returns the shared symmetric key between the client and the server.
 *
 * @return Pointer to a asymmetric key object.
 */
SymmetricKey *SecureClient::shared_key() {
  return m_shared_key;
}

/**
 * @name authenticate_server - Authenticate with a server.
 * @param: validate_func: A pointer to user provided validation function.
 * @param: parameter: Pointer to a data structure used as a parameter for
 *                    the user defined validate_func function.
 *
 * This function authenticates the client to the server. It first requests
 * the server's certificate. Then, it uses a uer provided function in order
 * to verify that the certificate has been signed by a a trusted CA or a
 * chain of CA's. This function must take as an argument a string that
 * contains the certificate contents. This string should be generated by
 * using the certificate's pack_to_string method. The function can also
 * take a second parameter which is a pointer to a user-defined data
 * structure. The user must properly cast the void type to the proper data
 * type. For example if the data type is TYPE then the user must do the
 * following:
 * TYPE *p = static_cast<TYPE*>(parameter);
 * If the validate_func argument is NULL, the function assumes that the
 * certificate is not valid and terminates.
 * Then, a AUTH_REQ message is send to the server and the server replies
 * with a AUTH_REP message that contains the shared symmetric key.
 */
int32_t SecureClient::authenticate_server(int32_t
					  (*validate_func)(const char *,
							   void *),
					  void *parameter) {
  if (!m_keypair || !m_certificate) {
    std::cerr << "Skytale::SecureClient::authenticate_server: Client's keypair or certificate is not set.\n";
    return 1;
  }
  
  std::string packet;
  std::string response;
  char *response_buf = NULL;
  Encoder enc;
  Decoder dec;

  this->set_client_id(m_keypair->public_key()->get_key_hash(SHA256_H));
  
  // [Step 1] CERT_REQ: Initiate authentication and request the server's certificate.
  // --------------------------------------------------------------------------------
  // Generate the CERT_REQ packet.
  // CERT_REQ: (AUTH_CERT_REQ:string)(CLIENT ID:string)
  packet.clear();
  enc.put(auth_operation(AUTH_CERT_REQ));
  enc.put(this->client_id());
  packet = enc.get();

  // Initiate authentication.
  if (this->send_data(packet.c_str(), packet.size()) == -1) {
    std::cerr << "Skytale::SecureClient::authenticate_server: Cannot send data to endpoint.\n";
    return 1;
  }
  
  // Wait for server's response.
  response_buf = new char[AUTH_MAX_PACKET_SIZE];
  memset(response_buf, 0, AUTH_MAX_PACKET_SIZE);
  if (this->receive_data(response_buf, AUTH_MAX_PACKET_SIZE) == -1) {
    std::cerr << "Skytale::SecureClient::authenticate_server: Cannot receive data from endpoint.\n";
    return 1;
  }
  
  response.assign(response_buf);
  delete response_buf;
  response_buf = NULL;
  
  // Check server's response.
  dec.put(response);
  if (dec.get<std::string>() != auth_operation(AUTH_CERT_REP)) {
    // Something strange happened. The server did not reply with a proper
    // packet format. We have to end the authentication process here.
    std::cerr << "Skytale::SecureClient::authenticate_server. Wrong packet format. AUTH_CERT_REP was expected. \n";
    return 1;
  }
  
  // Now extract the server's certificate and check its validity.
  std::string cert_str = dec.get<std::string>();
  Certificate cert;
  cert.unpack_from_string(cert_str);

  if (!(cert.is_valid(validate_func, parameter))) {
    // The certificate is not valid. We have to end the authentication process.
    std::cerr << "Skytale::SecureClient::authenticate_server: The server certificate is not valid.\n";
    return 1;
  }
  
  // [Step 2] AUTH_REQ: Request to create a secure session with the server.
  // -----------------------------------------------------------------------
  // Generate the AUTH_REQ packet.
  // AUTH_REQ: (AUTH_AUTH_REQ:string)(Es:string){(Tauth:time_t)(Kr:string)
  //            (iv:string)(Ec:string)(Eccert:string){(Kr:string)(iv:string)
  //            (Es:string)(KuEs:string)(Tauth:string}KrEc}KuEs

  packet.clear();
  enc.clear();

  // Server PK: Ku.
  std::string ku_str = cert.subject_pk();
  PublicKey ku;
  ku.load_from_string(ku_str);

  // Server ID: Es.
  std::string es = ku.get_key_hash(SHA256_H);

  // Current time: Tauth.
  time_t tauth = time(0);

  // Random symmetric key: Kr and IV: iv.
  SymmetricKey sk;
  sk.generate();
  std::string kr = sk.get_key_string();
  std::string iv = sk.get_iv_string();
  
  // Client ID: Ec.
  std::string ec = this->client_id();
  
  // Load These fields to the encoder.
  enc.put(tauth);
  enc.put(kr);
  enc.put(iv);
  enc.put(ec);
  enc.put(m_certificate->pack_to_string()); // Client certificate: Eccert.

  // We need a second encoder for the second part of the message.
  Encoder enc2;
  enc2.put(kr);
  enc2.put(iv);
  enc2.put(es);
  enc2.put(ku_str);
  enc2.put(tauth);
  std::string part2 = enc2.get();

  // Sign the second part of the message with the client's pricate key.
  std::string part2_sign = m_keypair->private_key()->sign_message(part2);

  // Put the second part and its signature into the first encoder.
  enc.put(part2);
  enc.put(part2_sign);

  // Extract the encoder contents and encrypt them with server's public key.
  std::string part1 = enc.get();
  std::string part1_encrypted = ku.encrypt_message(part1);

  // Now we are ready to build our packet.
  enc.clear();
  enc.put(auth_operation(AUTH_AUTH_REQ));
  enc.put(es);
  enc.put(part1_encrypted);
  packet = enc.get();
  
  // Send the packet.
  if (this->send_data(packet.c_str(), packet.size()) == -1) {
    std::cerr << "Skytale::SecureClient::authenticate_server: Cannot send data to endpoint.\n";
    return 1;
  }
  
  // Wait for server's response.
  response_buf = new char[AUTH_MAX_PACKET_SIZE];
  memset(response_buf, 0, AUTH_MAX_PACKET_SIZE);
  if (this->receive_data(response_buf, AUTH_MAX_PACKET_SIZE) == -1) {
    std::cerr << "Skytale::SecureClient::authenticate_server: Cannot receive data from the  endpoint.\n";
    return 1;
  }
  
  response.assign(response_buf);
  delete response_buf;
  response_buf = NULL;

  // Ckeck server's response.
  dec.clear();
  dec.put(response);
  
  // Packet Type.
  if (dec.get<std::string>() != auth_operation(AUTH_AUTH_REP)) {
    // Something strange happened. The server did not reply with a proper
    // packet format. We have to end the authentication process here.
    std::cerr << "Skytale::SecureClient::authenticate_server: Wrong packet format. AUTH_AUTH_REP was expected.\n";
    return 1;
  }

  // Next comes an encrypted part with the client's random symmetric key.
  std::string part_sencrypted = dec.get<std::string>();

  // Try to decrypt this part.
  std::string part_sdecrypted = sk.decrypt(part_sencrypted);

  // We need a second decoder now.
  Decoder dec2;
  dec2.put(part_sdecrypted);

  // This must be Client's identity.
  if (dec2.get<std::string>() != ec)
    return 1;
    
  // This must be server's id: es.
  if (dec2.get<std::string>() != es) {
    std::cerr << "Skytale::SecureClient::authenticate_server: Received server ID does not match the server's certificate.\n";
    return 1;
  }
  
  // Next comes the shared symmetric key between the server and the client
  // and the iv.
  std::string kr_retr = dec2.get<std::string>();
  std::string iv_retr = dec2.get<std::string>();
  if (m_shared_key)
    delete m_shared_key;
  m_shared_key = NULL;
  m_shared_key = new SymmetricKey();
  m_shared_key->set_key(kr_retr);
  m_shared_key->set_iv(iv_retr);

  // This should be the Tauth.
  if (dec2.get<time_t>() != tauth) {
    std::cerr << "Skytale::SecureClient::authenticate_server: Received timestamp does not match the sent timestamp.\n";
    return 1;
  }
  
  // Authentication succeeded.
  return 0;
}

/**
 * @name send_secure_data - Send encrypted data.
 * @param data: The data to send in plain form.
 * @param data_len: The length of the data.
 *
 * This function first encrypts the data using the shared symmetric key
 * and then it send the ciphertex by calling send_data.
 *
 * @return number of bytes sent or -1 on error.
 */
int32_t SecureClient::send_secure_data(const void *data, const size_t data_len) {
  if (m_shared_key) {
    std::string data_string(static_cast<const char *>(data));
    std::string encrypted = m_shared_key->encrypt(data_string);
    return send_data(encrypted.c_str(), strlen(encrypted.c_str()), NULL);
  } else {
    std::cerr << "Skytale::SecureClient::send_secure_data: Cannot send data to endpoint.\n";
    return -1;
  }
}

/**
 * @name receive_secure_data - Receive encrypted data.
 * @param data: The data buffer to store the received data,
 * @param data_len: The length of the data buffer.
 *
 * This function first receives the data in encrypted form. Then it 
 * decrypts the data using the shared symmetric key.
 *
 * @return number of bytes received (ciphertect)  or -1 on error.
 */
int32_t SecureClient::receive_secure_data(void *data, const size_t data_len) {
  if (m_shared_key) {
    int32_t ret = receive_data(data, data_len, NULL);
    if (ret != -1) {
      std::string data_string(static_cast<const char *>(data));
      std::string decrypted = m_shared_key->decrypt(data_string);
      if (strlen(decrypted.c_str()) <= data_len) {
	memset(data, 0, data_len);
	memcpy(data, decrypted.c_str(), strlen(decrypted.c_str()));
	return ret;
      }
    }
  }
  std::cerr << "Skytale::SecureClient::receive_secure_data: Cannot receive data from the endpoint.\n";
  return -1;
}

/**
 * @name SecureServer - Constructor.
 *
 * The default constructor.
 */
SecureServer::SecureServer() {
  m_keypair = NULL;
  m_certificate = NULL;
}

/**
 * @name SecureServer - Destructor.
 *
 * The default destructor.
 */
SecureServer::~SecureServer() {
  if (m_keypair)
    delete m_keypair;
  m_keypair = NULL;

  if (m_certificate)
    delete m_certificate;
  m_certificate = NULL;
}

/**
 * @name set_server_id - Set Server ID.
 * @param id: ID derived from server's public key.
 *
 * Sets the ID of the server.
 *
 * @return Void.
 */
void SecureServer::set_server_id(std::string id) {
  m_server_id = id;
}

/**
 * @name server_id - Get Server ID.
 *
 * Get the ID of the server.
 *
 * @return ID in string form.
 */
std::string SecureServer::server_id() {
  return m_server_id;
}

/**
 * @name set_certificate - Set server certificate.
 * @param certificate: Server certificate.
 *
 * Sets the server certificate.
 *
 * @return Void.
 */
void SecureServer::set_certificate(Certificate *certificate) {
  m_certificate = new Certificate(certificate);
}

/**
 * @name certificate - Return the certificate.
 *
 * Returns the server's certificate.
 *
 * @return Pointer to a certificate object.
 */
Certificate *SecureServer::certificate() {
  return m_certificate;
}

/**
 * @name set_keypair - Set server keypair.
 * @param keypair: Server's keypair.
 *
 * Sets the keypair.
 *
 * @return Void.
 */
void SecureServer::set_keypair(KeyPair *keypair) {
  m_keypair = new KeyPair(keypair);
}

/**
 * @name keypair - Return the keypair.
 *
 * Returns the server's keypair.
 *
 * @return Pointer to a keypair object.
 */
KeyPair *SecureServer::keypair() {
  return m_keypair;
}

/**
 * @name authenticate_client - Authenticate a client.
 * @param client - A pointer to a client object that we need to authenticate.
 * @param validate_func: A pointer to user provided validation function.
 * @param parameter: Pointer to a data structure used as a parameter for
 *                   the user defined validate_func function.
 *
 * This function authenticates a new client. It first requests
 * the server's certificate. Then, it uses a uer provided function in order
 * to verify that the certificate has been signed by a a trusted CA or a
 * chain of CA's. This function must take as an argument a string that
 * contains the certificate contents. This string should be generated by
 * using the certificate's pack_to_string method. The function can also
 * take a second parameter which is a pointer to a user-defined data
 * structure. The user must properly cast the void type to the proper data
 * type. For example if the data type is TYPE then the user must do the
 * following:
 * TYPE *p = static_cast<TYPE*>(parameter);
 * If the validate_func argument is NULL, the function assumes that the
 * certificate is not valid and terminates.
 * Then, a AUTH_REQ message is send to the server and the server replies
 * with a AUTH_REP message that contains the shared symmetric key.
 */
int32_t SecureServer::authenticate_client(SecureClient *client,
					  int32_t (*validate_func)(const char *, void *),
					  void *parameter) {
  if (!m_keypair || !m_certificate) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Server's keypair or certificate is not set.\n";
    return 1;
  }
  
  std::string packet;
  std::string response;
  char *response_buf = NULL;
  Encoder enc;
  Decoder dec;

  this->set_server_id(m_keypair->public_key()->get_key_hash(SHA256_H));
  
  // Wait for client's request.
  response_buf = new char[AUTH_MAX_PACKET_SIZE];
  memset(response_buf, 0, AUTH_MAX_PACKET_SIZE);
  if (this->receive_data(response_buf, AUTH_MAX_PACKET_SIZE, client) == -1) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Cannot receive data from the endpoint.\n";
    return 1;
  }
  
  response.assign(response_buf);
  delete response_buf;
  response_buf = NULL;

  // Check client's response.
  dec.put(response);
  if (dec.get<std::string>() != auth_operation(AUTH_CERT_REQ)) {
    // Something strange happened. The client did not send with a proper
    // packet format. We have to end the authentication process here.
    std::cerr << "Skytale::SecureServer::authenticate_client: Wrong packet format. AUTH_CERT_REQ was expected.\n";
    return 1;
  }
  // Extract the client ID.
  client->set_client_id(dec.get<std::string>());
  
  // [Step 1] CERT_REP: Initiate authentication by sending server's certificate.
  // ---------------------------------------------------------------------------
  // Generate the CERT_REP packet.
  // CERT_REP: (AUTH_CERT_REP:string)(Escert:string)
  packet.clear();

  // AUTH_CERT_REP
  enc.put(auth_operation(AUTH_CERT_REP));

  // Escert
  enc.put(m_certificate->pack_to_string());
  packet = enc.get();

  // Send the packet.
  if (this->send_data(packet.c_str(), packet.size(), client) == -1) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Cannot send data to the endpoint.\n";
    return 1;
  }
  
  // Wait for client's response.
  response_buf = new char[AUTH_MAX_PACKET_SIZE];
  memset(response_buf, 0, AUTH_MAX_PACKET_SIZE);
  if (this->receive_data(response_buf, AUTH_MAX_PACKET_SIZE, client) == -1) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Cannot receive data from the endpoint.\n";
    return 1;
  }
  
  response.assign(response_buf);
  delete response_buf;
  response_buf = NULL;

  // Check client's response.
  dec.clear();
  dec.put(response);

  // Packet type.
  if (dec.get<std::string>() != auth_operation(AUTH_AUTH_REQ)) {
    // Something strange happened. The client did not reply with a proper
    // packet format. We have to end the authentication process here.
    std::cerr << "Skytale::SecureServer::authenticate_client: Wrong packet format. AUTH_AUTH_REQ was expected.\n";
    return 1;
  }
  // Next comes the server's ID.
  if (dec.get<std::string>() != this->server_id()) {
    // Something strange happened. The ID of the server does not match the ID of the
    // requested server.
    std::cerr << "Skytale::SecureServer::authenticate_client: Received server ID does not match the real server's ID.\n";
    return 1;
  }
  // Next comes the encrypted part. This part is encrypted with the server's public key.
  std::string encrypted1 = dec.get<std::string>();
  
  // Decrypt this part.
  std::string decrypted1 = m_keypair->private_key()->decrypt_message(encrypted1);

  // Load the decrypted part into the decoder.
  dec.clear();
  dec.put(decrypted1);
  
  // Extract Tauth.
  time_t tauth = dec.get<time_t>();

  time_t now = time(0);
  if (tauth > (now + AUTH_MAX_TIME_SKEW) || (tauth + AUTH_MAX_TIME_SKEW) < now) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Time skew was detected.\n";
    return 1;
  }
  
  // Extract the random symmetric key.
  std::string kr_str = dec.get<std::string>();

  // Extract the key iv.
  std::string iv_str = dec.get<std::string>();

  // Extract client ID.
  if (client->client_id() != dec.get<std::string>()) {
    // Wrong client ID.
    std::cerr << "Skytale::SecureServer::authenticate_client: Wrong client ID.\n";
    return 1;
  }
  
  // Extract the client certificate.
  std::string eccert_str = dec.get<std::string>();
  Certificate eccert;
  eccert.unpack_from_string(eccert_str);
  client->set_certificate(&eccert);
  
  // Check client certificate.
  if (!(eccert.is_valid(validate_func, parameter))) {
    // The certificate is not valid. We have to end the authentication process.
    std::cerr << "Skytale::SecureServer::authenticate_client: Client certificate is note valid.\n";
    return 1;
  }
  
  // Next comes a second part which is also signed by the client.
  std::string signed1 = dec.get<std::string>();
  std::string signature = dec.get<std::string>();

  // Verify signature with client's public key.
  PublicKey kuec;
  kuec.load_from_string(eccert.subject_pk());
  if (!(kuec.verify_message(signed1, signature))) {
    // Signature is not valid.
    std::cerr << "Skytale::SecureServer::authenticate_client: Message signature is not valid.\n";
    return 1;
  }

  // Now load the signed part into a second decoder.
  Decoder dec2;
  dec2.put(signed1);

  // Extract the random symmetric key and valdiate it
  if (dec2.get<std::string>() != kr_str) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Failed to validate the received random symmetric key (kr).\n";
    return 1;
  }
  
  // Extract the key iv and validate it.
  if (dec2.get<std::string>() != iv_str) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Failed to validate the received random iv (iv).\n";
    return 1;
  }
  
  // Extract the server id and valdiate it.
  if (dec2.get<std::string>() != this->server_id()) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Failed to validate the received Server ID.\n";
    return 1;
  }

  // Extract the server's public key and valdiate it.
  if (dec2.get<std::string>() != m_keypair->public_key()->get_key_string()) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Failed to validate the received server's public key.\n";
    return 1;
  }
  
  // Extract the tauth and valdiate it.
  if (dec2.get<time_t>() != tauth) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Failed to validate the received timestamp (tauth).\n";
    return 1;
  }
  
  // [Step 2] AUTH_REP: Create a secure session with the client.
  // ------------------------------------------------------------
  // Generate the AUTH_REP packet.
  // AUTH_REP: (AUTH_AUTH_REP:string){(Ec:string)(Es:string)
  //            (keces:string)(iveces:string)(tauth:time_t)}kr
  //            Teces: (Es:string){(keces:string)(iveces:string)(Ec:string)
  //                   (tauth:time_t)}kes

  packet.clear();
  enc.clear();

  // Ec
  enc.put(client->client_id());

  // Es
  enc.put(this->server_id());

  // keces, iveces
  // Generate a random symmetric key for the session.
  SymmetricKey keces;
  keces.generate();
  client->set_shared_key(&keces);
  enc.put(keces.get_key_string());
  enc.put(keces.get_iv_string());
  enc.put(tauth);
  SymmetricKey kr;
  kr.set_key(kr_str);
  kr.set_iv(iv_str);

  // Encrypt the above part.
  encrypted1 = enc.get();
  encrypted1 = kr.encrypt(encrypted1);
  
  // Build the whole packet now.
  enc.clear();
  enc.put(auth_operation(AUTH_AUTH_REP));
  enc.put(encrypted1);
  packet = enc.get();

  // Send the packet.
  if (this->send_data(packet.c_str(), packet.size(), client) == -1) {
    std::cerr << "Skytale::SecureServer::authenticate_client: Cannot sent data to the endpoint.\n";
    return 1;
  }
  
  return 0;
}

/**
 * @name send_secure_data - Send encrypted data.
 * @param data: The data to send in plain form.
 * @param data_len: The length of the data.
 * @param client: The client endpoint where the data will be sent.
 *
 * This function first encrypts the data using the shared symmetric key
 * and then it send the ciphertex by calling send_data.
 *
 * @return number of bytes sent or -1 on error.
 */
int32_t SecureServer::send_secure_data(const void *data, const size_t data_len,
				       SecureClient *client) {
  if (client) {
    if (client->shared_key()) {
      std::string data_string(static_cast<const char *>(data));
      std::string encrypted = client->shared_key()->encrypt(data_string);
      return send_data(encrypted.c_str(), strlen(encrypted.c_str()), client);
    }
  }
  std::cerr << "Skytale::SecureServer::send_secure_data: Cannot sent data to the endpoint.\n";
  return -1;
}

/**
 * @name receive_secure_data - Receive encrypted data.
 * @param data: The data buffer to store the received data,
 * @param data_len: The length of the data buffer.
 * @client: The client endpoint from where the data will be received.
 *
 * This function first receives the data in encrypted form. Then it 
 * decrypts the data using the shared symmetric key.
 *
 * @return number of bytes received (ciphertect)  or -1 on error.
 */
int32_t SecureServer::receive_secure_data(void *data, const size_t data_len,
					  SecureClient *client) {
  if (client) {
    if (client->shared_key()) {
      int32_t ret = receive_data(data, data_len, client);
      if (ret != -1) {
	std::string data_string(static_cast<const char *>(data));
	std::string decrypted = client->shared_key()->decrypt(data_string);
	if (strlen(decrypted.c_str()) <= data_len) {
	  memset(data, 0, data_len);
	  memcpy(data, decrypted.c_str(), strlen(decrypted.c_str()));
	  return ret;
	}
      }
    }
  }
  std::cerr << "Skytale::SecureServer::receive_secure_data: Cannot receive data from the endpoint.\n";
  return -1;
}

