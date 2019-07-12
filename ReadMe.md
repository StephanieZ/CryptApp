<h4>C# DES Encryption and Decryption</h4>

Sometimes developers have a need to verify passwords from Unix-based systems on Windows-based applications. This presents an issue, in that .NET crypto libraries like CryptSharp© do not support a subset of the salts that Unix does. They flat out fail to encrypt or they throw an invalid salt exception. So this library is intended to expand the existing .NET crypto libraries so they all the salts that are acceptable to Unix are also acceptable to your .NET Windows application
