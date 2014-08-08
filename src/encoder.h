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
#ifndef ENCODER_H
#define ENCODER_H

#include <string>
#include <sstream>
#include <stdint.h>
#include <typeinfo>

namespace Skytale {

/** 
 * @name Encoder - Encoder object.
 *
 * This class defines the encoder object. To encode the value of a variable
 * just call the put method with the variable as a parameter. To get the
 * encoded string use the get smethod.
 */ 
class Encoder
{
private:
  uint32_t m_elements;
  std::string m_sizes;
  std::string m_payload;
public:
  Encoder();
  ~Encoder();

  /**
   * @name put - Encode a new value.
   * @param T element: The value to be decoded
   *
   * This method initializes the encoder object.
   *
   * @return Void.
   */
  template<typename T>  
  void put(const T element) {
    std::stringstream ss1, ss2;
    
    m_elements++;
    ss2 << element;
    m_payload += ss2.str();
    ss1 << ss2.str().length() <<' ';
    m_sizes += ss1.str();
  }
  
  std::string get();
  void clear();
};

/** 
 * @name Decoder - Decoder object.
 *
 * This class defines the decoder object. To Load a value use the
 * constructor or the put method, To decode a value with type "TYPE" call
 * the decode method like this: TYPE result = get<TYPE>();
 */ 
class Decoder
{
private:
  uint32_t m_elements;
  uint32_t m_current;
  uint32_t *m_sizes;
  std::string m_payload;
public:
  Decoder(const std::string in);
  Decoder();
  ~Decoder();

  void put(const std::string in);

  /**
   * @name get - Loads a string to the decoder.
   * @param in: A string that contains encoded values.
   *
   * This method loads a string to the decoder object. It must be called
   * only once. If you use the constructor to load string you should not
   * call this method.
   *
   * @return The current decoded value.
   */
  template<typename T>
  inline T get(){
    if (m_current < m_elements && !(m_payload.empty())) { 
      std::string result = m_payload.substr(0, m_sizes[m_current]);
      m_payload = m_payload.substr(m_sizes[m_current], m_payload.length());
      T ret;
      std::stringstream ss(result);
      // Call a helper function to handle strings differently from other types.
      get_impl(ss, ret);
      
      m_current++;
      return ret;
    } else {
      // The payload is empty, return 0.
      std::string result = "0";
      T ret;
      std::stringstream ss(result);
      ss >> ret;
      return ret;
    }
  }
  
  void clear();

 private:
  void get_impl(std::stringstream &ss, std::string &param) {
    param = ss.str();
  }
  
  template<typename T>
  void get_impl(std::stringstream &ss, T &param) {
    ss >> param;
  }
  
};

}

#endif
