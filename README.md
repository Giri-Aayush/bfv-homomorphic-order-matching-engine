# BFV Homomorphic Order Matching Engine

## Overview
The BFV Homomorphic Order Matching Engine is a Rust-based project that demonstrates the use of homomorphic encryption for secure and privacy-preserving order matching in financial trading systems. The project utilizes the BFV (Brakerski-Fan-Vercauteren) encryption scheme to perform computations on encrypted order data without revealing the underlying values.

## Problem Statement
In traditional order matching systems, sensitive order information, such as buy and sell order values, is processed and matched in plaintext. This poses privacy and security risks, as the order data is exposed to potential breaches and unauthorized access. Additionally, the lack of confidentiality may hinder the participation of certain entities in the trading system.

## Solution
The BFV Homomorphic Order Matching Engine addresses these challenges by leveraging homomorphic encryption. The project enables secure order matching while preserving the confidentiality of the order data. The key features of the solution include:

- **Encryption**: Buy and sell orders are encrypted using the BFV encryption scheme, ensuring that the order values remain confidential throughout the matching process.
- **Homomorphic Operations**: The engine performs homomorphic addition and comparison operations on the encrypted order data. This allows for the matching of buy and sell orders without decrypting the values.
- **Secure Matching**: The engine determines the transaction volume based on the encrypted sums of buy and sell orders. It then fills the orders based on the available volume while maintaining the confidentiality of the order values.
- **Decryption**: The filled orders are decrypted and decoded only at the end of the process, revealing the matched orders and their respective values to the authorized parties.

## Demo
Here's a sample output of the BFV Homomorphic Order Matching Engine:
![alt text](demo.png)