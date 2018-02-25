/*
 * Copyright (c) 2018, Eduardo Fuentetaja. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the WebSocket++ Project nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL PETER THORSON BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PEMEXTRACTOR_HPP__D0C7FEB1557349A59AC909104AF006B6
#define PEMEXTRACTOR_HPP__D0C7FEB1557349A59AC909104AF006B6

#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include <assert.h>
#include <iostream>
#include <vector>
#include <string>

#include <boost/shared_array.hpp>

/* Simple PKCS#12 file reader */

class PEMExtractor
{
private:
    struct Buffer
    {
        unsigned int length;
        boost::shared_array<char> data;

        Buffer() : length(0)
        {
            // Does nothing
        }

        void reset()
        {
            if (length > 0) {
                // Before releasing the memory, set to 0xFF and then to 0
                memset(data.get(), 0xFF, length);
                memset(data.get(), 0x0, length);
                data.reset();
            }
        }
    };

    Buffer private_key;
    Buffer certificate;
    std::vector<Buffer> certificate_stack;

    /**
     * \return 0 if everything is alright, 1 otherwise
     */
    int extract_key(EVP_PKEY *pkey)
    {
        BIO* key_bio = BIO_new(BIO_s_mem());
        int result = PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL);
        if (!result) {
            ERR_print_errors_fp(stderr);
        }
        char* buffer;
        private_key.length = (unsigned int)BIO_get_mem_data(key_bio, &buffer);
        private_key.data = boost::shared_array<char>(new char[private_key.length]);
        memcpy(private_key.data.get(), buffer, private_key.length);
        BIO_free(key_bio);

        return result;
    }

    /**
     * \return 0 if everything is alright, 1 otherwise
     */
    int extract_certificate(X509 *cert)
    {
        BIO* cert_bio = BIO_new(BIO_s_mem());
        int result = PEM_write_bio_X509_AUX(cert_bio, cert);
        if (!result) {
            ERR_print_errors_fp(stderr);
        }

        char* buffer;
        certificate.length = (unsigned int)BIO_get_mem_data(cert_bio, &buffer);
        certificate.data = boost::shared_array<char>(new char[certificate.length]);
        memcpy(certificate.data.get(), buffer, certificate.length);
        BIO_free(cert_bio);

        return result;
    }

    /**
     * \return 0 if everything is alright, 1 otherwise
     */
    int extract_certificate_stack(STACK_OF(X509) *ca)
    {
        int result = 1;
        unsigned int n = sk_X509_num(ca);
        certificate_stack.reserve(n);

        for (unsigned int i = 0; i < n; i++) {
            BIO* cert_bio = BIO_new(BIO_s_mem());
            result &= PEM_write_bio_X509_AUX(cert_bio, sk_X509_value(ca, i));
            if (!result) {
                ERR_print_errors_fp(stderr);
            }

            char* buffer;
            Buffer item;
            item.length = (unsigned int)BIO_get_mem_data(cert_bio, &buffer);
            item.data = boost::shared_array<char>(new char[item.length]);
            memcpy(item.data.get(), buffer, item.length);
            BIO_free(cert_bio);

            certificate_stack.push_back(item);
        }

        return result;
    }

public:
    PEMExtractor()
    {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    unsigned int get_private_key(char** out_buffer)
    {
        *out_buffer = private_key.data.get();
        return private_key.length;
    }

    unsigned int get_certificate(char** out_buffer)
    {
        *out_buffer = certificate.data.get();
        return certificate.length;
    }

    unsigned int get_certificate_stack_size()
    {
        return (unsigned int)certificate_stack.size();
    }

    unsigned int get_certificate_stack_item(unsigned int i, char** out_buffer)
    {
        *out_buffer = certificate_stack[i].data.get();
        return certificate_stack[i].length;
    }

    /**
     * \return 0 if everything is alright, 1 or a negative number otherwise
     */
    int process_p12_file(std::string a_p12_file_path, std::string password)
    {
        PKCS12 *p12 = NULL;

        int result = 0;

        {
            FILE *fp;
            if (!(fp = fopen(a_p12_file_path.c_str(), "rb"))) {
                result = -1;
            } else {
                p12 = d2i_PKCS12_fp(fp, NULL);
                fclose (fp);
            }
        }

        if (! p12) {
            ERR_print_errors_fp(stderr);
            result = -2;
        } else {
            // Extract the PK and certificates

            EVP_PKEY *pkey;
            X509 *cert;
            STACK_OF(X509) *ca = NULL;

            if (!PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca)) {
                ERR_print_errors_fp(stderr);
                result = -3;
            } else {
                // OK so far
                if (pkey) {
                    result &= extract_key(pkey);
                    EVP_PKEY_free(pkey);
                }
                if (cert) {
                    result &= extract_certificate(cert);
                    X509_free(cert);
                }
                if (ca) {
                    result &= extract_certificate_stack(ca);
                    sk_X509_pop_free(ca, X509_free);
                }
            }

            PKCS12_free(p12);
        }

        return result;
    }

    void reset()
    {
        private_key.reset();
        certificate.reset();

        for (std::vector<Buffer>::iterator it = certificate_stack.begin(); it != certificate_stack.end(); ++it) {
            it->reset();
        }
        certificate_stack.clear();
    }

    static void test()
    {
        PEMExtractor extractor;

        int result;
    
        result = extractor.process_p12_file("D:\\ed\\WORK\\WebSockets\\certificate\\domain.pfx", "secretpassword");
        std::cout << result << std::endl;

        unsigned int length;
        char* buffer;

        length = extractor.get_private_key(&buffer);
        std::string private_key(buffer, length);
        std::cout << private_key << std::endl;

        length = extractor.get_certificate(&buffer);
        std::string certificate(buffer, length);
        std::cout << certificate << std::endl;

        unsigned int certificate_stack_size = extractor.get_certificate_stack_size();
        for (unsigned int i=0; i<certificate_stack_size; i++) {
            length = extractor.get_certificate_stack_item(i, &buffer);
            std::string item(buffer, length);
            std::cout << item << std::endl;
        }
    }

};

#endif // PEMEXTRACTOR_HPP__D0C7FEB1557349A59AC909104AF006B6
