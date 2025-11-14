#include <iostream>
#include "cxxopts.hpp" //Library for argument parsing
#include <boost/multiprecision/gmp.hpp> //library for dealing with big integer
#include <chrono> //Library for meaasuring time 
                  //Library for plotting results 
#include <openssl/rand.h> // Library for cryptographically secure random numbers
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <thread>
#include <vector>
#include <openssl/bn.h>
#include <utility>
#include "primes.h" // SMALL_PRIMES to verify before Miller-Rabin


using namespace boost::multiprecision; 

void print_bn_dec(const char* label, const BIGNUM* bn) {
    
    char* dec_str = BN_bn2dec(bn); 
    
    if (dec_str) {
        
        std::cout << label << " (dec): " << dec_str << std::endl;
        OPENSSL_free(dec_str); 
    } else {
        std::cerr << "Error during conversion:  " << label << std::endl;
    }
}


bool fast_prime_filter(mpz_int& number){
    // Early checks for trivial cases
    if (number < 2) return false;
    if (number == 2) return true;

    for (unsigned int p: SMALL_PRIMES){
        if (number % p == 0){
            return false;
        }
    }

    return true; 
}


mpz_int random_integer_x_bits(int bits){

    mpz_int value = 0; 
    int total_bytes = (bits + 7)/8;
     
    std::vector<unsigned char> buffer(total_bytes); 

    if (RAND_bytes(buffer.data(), total_bytes) != 1){
        throw std::runtime_error("Error: Random RAND_bytes failed");
    }

    for (int i = 0; i < total_bytes; ++i){
        value <<=8; 
        value |= buffer[i]; 
    }
    
    int excess_bits = (total_bytes * 8) - bits; 
    if (excess_bits > 0){
        value >>= excess_bits; 
    }

    // Force the number to be the correct number of bits 
    value |= mpz_int(1) << (bits-1);
    // Forces the number to be odd
    value |= mpz_int(1);
    return value; 
}


bool Miller_Rabin_primality_test(mpz_int& n, int bits){

    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0) return false;
    // Find d and s such that n-1 = 2^s * d
    
    mpz_int d = n -1; 
    int s = 0; 
    while (d % 2 == 0){
        d /= 2; 
        s++; 
    }
   
    // Selects a random base 'a' for the Miller-Rabin test, ensuring it lies
    // within the required range of [2, n - 2] using modulo.
    mpz_int a = random_integer_x_bits(bits) % (n - 3) + 2;
    
    // Compute x = a^d mod n 
    // if x = 1 or x = n-1 n passes the round 
    mpz_int x = powm(a, d, n); 
    if (x == 1 || x == n-1){
        return true; 
    }


    // repeat squaring and check
    for (int i = 0; i < s-1; ++i){
        x = powm(x,2,n);
        if (x == 1){
            return false; 
        } else if (x == n-1){
          return true; 
        }

    }


    return false; // Composite
}

bool check_primality(mpz_int& number, int bits, int n_tests){

    for (int i = 0; i < n_tests; ++i){
        if (!Miller_Rabin_primality_test(number, bits))
           return false;  
    }
    
    return true; 

}

std::pair<mpz_int, mpz_int> generate_prime_naive(int size){
    mpz_int p = random_integer_x_bits(size);
            
    while (!check_primality(p, size, 50)){
        p = random_integer_x_bits(size);
    }
        
    std::cout << "Found p: " << p << std::endl; 
                                                
    mpz_int q = random_integer_x_bits(size);
    while (!check_primality(q, size, 50)){
        q = random_integer_x_bits(size);
    }
    std::cout << "Found q: " << q << std::endl; 
    return {p, q}; 

}

std::pair<mpz_int, mpz_int> generate_prime_optimized(int size){
    


    mpz_int p = random_integer_x_bits(size);
            
    while (!fast_prime_filter(p) || !check_primality(p, size, 50)){
        p = random_integer_x_bits(size);
    }
    
    std::cout << "Found p: " << p << std::endl; 
                                        
    mpz_int q = random_integer_x_bits(size);
    while (!fast_prime_filter(q) || !check_primality(q, size, 50)){
        q = random_integer_x_bits(size);
    }
    std::cout << "Found q: " << q << std::endl; 
    return {p, q}; 
}



std::tuple<mpz_int, mpz_int, mpz_int> compute_RSAkey_naive(mpz_int p, mpz_int q){
    
    mpz_int n = p * q; 
    mpz_int phi_n = (p-1) * (q-1); 
    mpz_int d; 
    mpz_int e = 3; 
    mpz_int result;

    //Naive search for a valid e
    while (true){

        result = gcd(e, phi_n); 
        if (result == 1){
        break; 
        } else {
            e += 2; 
        }
    }

    if (mpz_invert(d.backend().data(),
                   e.backend().data(),
                   phi_n.backend().data()) == 0)
    {
        throw std::runtime_error("Modular inverse does not exist for these values.");
    }
     
    //std::cout << "Private key ( " << d << ":" << e << ")" << std::endl;
    //std::cout << "Public key ( " << e << ":" << n << ")" << std::endl; 

    return std::make_tuple(e,d,n); 

}

std::tuple<mpz_int, mpz_int, mpz_int> compute_RSAkey_optimized(mpz_int p, mpz_int q){
        
    mpz_int n = p * q; 
    mpz_int phi_n = (p-1) * (q-1); 
    mpz_int e = 65537;         
    mpz_int d; 

    if (mpz_invert(d.backend().data(), e.backend().data(), phi_n.backend().data()) == 0) {
                       throw std::runtime_error("Modular inverse does not exist for these values.");
    }

    //std::cout << "Private key ( " << d << ":" << n << ")" << std::endl; 
    //std::cout << "Public key ( " << e << ":" << n << ")" << std::endl; 
    return std::make_tuple(e,d,n); 

}

mpz_int generate_message(std::string message){

    mpz_int m = 0 ; 
    for (auto c: message){
        m <<=8; 
        m += c; 
    }

    return m;
}

std::string retrieve_message(mpz_int& m){
    
    mpz_int temp = m;
    std::string message; 
    char c; 
    while (temp > 0){
        c = static_cast<int>(temp & 0xFF); 
        message = c + message;  
        temp >>= 8; 
    }
    return message; 
}

int compute_RSA(mpz_int& e, mpz_int& d, mpz_int& n, std::string message){

    std::string plaintext; 
    mpz_int m, c, m_computed; 

    m = generate_message(message); 


    // c = m^e mod n; 
    c = powm(m,e,n); 
    std::cout << "Ciphertext: " << c << std::endl; 

    m_computed = powm(c,d,n); 
    plaintext = retrieve_message(m_computed); 
    std::cout << "Plaintext: " << plaintext << std::endl; 

    return 0; 
}

int openssl_RSA(int bits, std::string message){

    unsigned long e = RSA_F4; 
    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();
    if (!BN_set_word(bne, e)) {
        std::cerr << "Error BN_set_word\n";
        return 1;
    }

    if (!RSA_generate_key_ex(rsa, bits, bne, nullptr)) {
        std::cerr << "Error in RSA key generation\n";
        return 1;
    }

    BN_free(bne);

    unsigned char encrypted[1024]; // RSA 2048 -> max 256 byte
    unsigned char decrypted[1024];
    int encrypted_length = RSA_public_encrypt(
        message.size(),
        reinterpret_cast<const unsigned char*>(message.c_str()),
        encrypted,
        rsa,
        RSA_PKCS1_OAEP_PADDING
    );

    if (encrypted_length == -1) {
        char buf[130];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), buf);
        std::cerr << "Error encryption: " << buf << "\n";
        RSA_free(rsa);
        return 1;
    }

    std::cout << "Ciphertext message (hex): ";
    for (int i = 0; i < encrypted_length; i++)
        printf("%02X", encrypted[i]);
    std::cout << "\n";

    // Decrypting
    int decrypted_length = RSA_private_decrypt(
        encrypted_length,
        encrypted,
        decrypted,
        rsa,
        RSA_PKCS1_OAEP_PADDING
    );

    if (decrypted_length == -1) {
        char buf[130];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), buf);
        std::cerr << "Error decryption: " << buf << "\n";
        RSA_free(rsa);
        return 1;
    }

    std::string decrypted_msg(reinterpret_cast<char*>(decrypted), decrypted_length);
    std::cout << "Plain Text: " << decrypted_msg << "\n";

    RSA_free(rsa);
    return 0;



}

int main(int argc, char* argv[]){

    cxxopts::Options options("RSA", "Amazing program that computes RSA with large primes :)");

    options.add_options()
        ("t, test", "Define the type of test: openssl, optimized, naive", cxxopts::value<std::string>())
        ("n, number", "Define number of bits for integers", cxxopts::value<int>())
        ("m, message", "Message to encrypt/decrypt", cxxopts::value<std::string>()); 
    try {

        auto result = options.parse(argc, argv);
        std::string message; 
        std::string test_type; 
        mpz_int e,d,n; 
        if (argc != 7){
            throw cxxopts::exceptions::exception("No input provided");
        }
    
        if (result.count("number")){
            int n = result["number"].as<int>();
            
            if (result.count("test")){
                test_type = result["test"].as<std::string>();
                if (result.count("message")){
                    message = result["message"].as<std::string>();
                } else {
                    throw cxxopts::exceptions::exception("No message to encrypt/decrypt"); 
                }

                if (test_type == "openssl"){
                    openssl_RSA(n, message); 

                } else if (test_type == "optimized") {
                        auto [p,q] = generate_prime_optimized(n);
                        auto [e,d,n] = compute_RSAkey_optimized(p, q);
                        compute_RSA(e,d,n,message); 

                } else if (test_type == "naive"){
                        auto [p, q] = generate_prime_naive(n); 
                        auto [e,d,n] = compute_RSAkey_naive(p, q); 
                        compute_RSA(e,d,n,message); 

                } else {
                throw cxxopts::exceptions::exception("No test selected"); 
                }

            }
            std::cout << "Size of bits used: " << n << std::endl; 
            


        }   

    
    } catch (const cxxopts::exceptions::exception& e){

        std::cerr << "Error: " << e.what() << std::endl; 
        std::cout << options.help() << std::endl; 
        return 1; 
    }

    return 0; 
}
