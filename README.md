Skytale - A high-level cryptographic and authentication library
===============================================================

Skytale is a high-level cryptographic and authentication library for C++. It is based
on Crypto++ for all the low-level cryptographic operations and on libiris for basic
network communication. Its main goals are strong security, simplicity, and usability. 

Please note that Skytale is still under heavy development and new features are introduced 
constantly, so do not consider it stable at this time for production environments.
Use it for testing purposes only.


Building and installing Skytale
-------------------------------

To build Skytale you need ton install Crypto++ library first. Please refer to this 
[link](http://www.cryptopp.com/wiki/Linux).

To build Skytale just type:
   `make`

To build a development version of Skytale with support for debugging 
symbols type:
   `make dev`

To build only the tests type:
   `make tests`

To install the Skytale library, run the following as root:
   `make install`
	

Removing Skytale
----------------

To remove the Skytale library type as root:
   `make remove`


Testing Skytale
-----------------

We have included several tests which check whether the Skytale library
works correctly. Check the `tests` folder for details. Note that at 
this point of development new tests are added to this folder constantly.


Supported cryptographic primitives
----------------------------------

* **Encryption**: The library supports public-key based and symmetric encryption. For 
  public-key encryption it uses the RSA algorithm, while for symmetric key encryption
  it uses the AES algorithm.
* **Signature/Verification**: The library supports private-key based signatures. For this
  reason it relies on RSA and Signature Scheme with Recovery (PSSR).
* **Message digests**: The library support the generation and validation of message digests.
  Message digests rely on SHA256.
* **Hashing**: Hashes of public keys are always supported. The user can choose one of the 
  following hash algorithms: SHA256/SHA384/SHA512/RIPEMD128/RIPEMD160/RIPEMD256/RIPEMD320/
  MD5/CRC32.


Using Skytale
-------------

To use the Skytale library you need to include `#include <skytale/xxxx.h`
into your C++ source file. The xxxx part can be 'encryption', 'digest', 'authentication'. Then, 
providing you have installed Skytale and Crypto++ into your system, you can build your 
application as follows:
   
   `$(CC) -o application_binary application.cc -lskytale -lcryptopp`


Development and Contributing
----------------------------

The initial developer of Skytale is [Giorgos Kappes](http://cs.uoi.gr/~gkappes). Feel free to 
contribute to the development of Skytale by cloning the repository: 
`git clone https://github.com/geokapp/Skytale`.
You can also send feedback, new feature requests, and bug reports to <geokapp@gmail.com>.
The library is currently under heavy development.
