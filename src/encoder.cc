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
#include <sstream>
#include <string.h>
#include "encoder.h"

using namespace Skytale;

/**
 * @name Encoder - Constructor.
 *
 * This method initializes the encoder object.
 */
Encoder::Encoder()
{
  m_elements = 0;
  m_sizes.clear();
  m_payload.clear();
}

/**
 * @name ~Encoder - Destructor.
 *
 * This method clears the encoder object.
 */
Encoder::~Encoder()
{
  m_elements = 0;
  m_sizes.clear();
  m_payload.clear();
}

/**
 * @name put - Encode a new value.
 * @param T element: The value to be decoded
 *
 * This method initializes the encoder object.
 *
 * @return Void.
 */
template<typename T>		
void Encoder::put(const T element) 
{
  std::stringstream ss1, ss2;
  
  m_elements++;
  ss2 << element;
  m_payload += ss2.str();
  ss1 << ss2.str().length() <<' ';
  m_sizes += ss1.str();
}

/**
 * @name get - Get the result string.
 *
 * This method returns a string that contains all the encoded values.
 *
 * @return A string that contains the encoded values.
 */
std::string Encoder::get() 
{
  std::stringstream ss;
  
  ss << m_elements <<' ' << m_sizes << m_payload;
  return ss.str();
}

/**
 * @name Decoder - Constructor.
 * @param in: A string that contains encoded values.
 *
 * This method initializes a decoder object.
 */
Decoder::Decoder(const std::string in) 
{
  put(in);
}

/**
 * @name Decoder - Constructor.
 *
 * This method initializes a decoder object.
 */
Decoder::Decoder() 
{
  m_payload.clear();
  m_sizes = NULL;
  m_elements = 0;
}

/**
 * @name ~Decoder - Destructor.
 *
 * This method clears  a decoder object.
 */
Decoder::~Decoder() 
{
  delete m_sizes;
}

/**
 * @name put - Loads a string to the decoder.
 * @param in: A string that contains encoded values.
 *
 * This method loads a string to the decoder object. It must be called
 * only once. If you use the constructor to load a string you should not
 * call this method.
 *
 * @return Void.
 */
void Decoder::put(const std::string in)
{
  if (m_payload.empty()) {
    // Load a string to the decoder only if the payload is empty.
    std::stringstream ss(in);
    m_current = 0;
    ss >> m_elements;
    m_sizes = new uint32_t[m_elements];
    for (uint32_t i = 0; i < m_elements; i++ )		
      ss >> m_sizes[i];
    
    ss >> m_payload;
  }
}

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
T Decoder::get() 
{
  if (m_current < m_elements && !(m_payload.empty())) {
    std::string result = m_payload.substr(0, m_sizes[m_current]);
    m_payload = m_payload.substr(m_sizes[m_current], m_payload.length());
    T ret;
    std::stringstream ss(result);
    ss >> ret;
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
