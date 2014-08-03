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
#ifndef ENCODER_H

#include <iostream>
#include <string>
#include <sstream>
#include <stdint.h>

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
  
  template<typename T>  
  void put(const T element);
  std::string get();
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
  template<typename T>
  T get();
};

}

#endif
