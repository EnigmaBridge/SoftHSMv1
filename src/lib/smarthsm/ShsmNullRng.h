//
// Created by Dusan Klinec on 26.06.15.
//

#ifndef SOFTHSMV1_SHSMNULLRNG_H
#define SOFTHSMV1_SHSMNULLRNG_H

#include <botan/rng.h>

/**
 * Random number generator producing constant output.
 * Used in unit testing. Do not use in production under any circumstances.
 */
class ShsmNullRng : public Botan::RandomNumberGenerator {

public:
    virtual void randomize(Botan::byte output[], size_t length);

    virtual void clear();

    virtual std::string name() const;

    virtual void reseed(size_t bits_to_collect);

    virtual void add_entropy_source(Botan::EntropySource *source);

    virtual void add_entropy(const Botan::byte in[], size_t length);
};


#endif //SOFTHSMV1_SHSMNULLRNG_H
