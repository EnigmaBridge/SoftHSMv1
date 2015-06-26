//
// Created by Dusan Klinec on 26.06.15.
//

#include "ShsmNullRng.h"
#include <string>

void ShsmNullRng::randomize(Botan::byte output[], size_t length) {
    memset(output, 0xab, length);
}

void ShsmNullRng::clear() {

}

std::string ShsmNullRng::name() const {
    return "ShsmNullRng";
}

void ShsmNullRng::reseed(size_t bits_to_collect) {

}

void ShsmNullRng::add_entropy_source(Botan::EntropySource *source) {

}

void ShsmNullRng::add_entropy(const Botan::byte in[], size_t length) {

}
