/* SHIRE link-security configuration for the simulated radio path.
**
** CryptoLib runs at both ends of the radio link: the ground standalone
** (support/standalone) applies security to commands and processes telemetry,
** and the flight radio app does the reverse. Both start from Crypto_SC_Init()
** and must then agree on which security associations protect each direction,
** so both call this one function.
**
**   Uplink   (TC, radio RX): VCID 0 -> SPI 4, AES-256-GCM encrypt + authenticate
**                            (clear-mode SPI 1 otherwise)
**   Downlink (TM, radio TX): VCID 1 -> SPI 6, AES-256-GCM encrypt + authenticate
**                            (clear-mode SPI 5 otherwise)
**
** Each SA keeps the last IV/ARSN it accepted, and a receiver only accepts a frame whose IV is ahead of that.
** A sender transmits with its current IV and then increments, so the end that sends on an SA must start one
** ahead of the end that receives on it; otherwise the very first frame (IV 0) is rejected as a replay. The
** ground sends TC and receives TM, the flight end the reverse.
**
** Keys come from CryptoLib's built-in in-memory key ring (the same test keys on
** both ends), so this protects a simulation, not a real link.
*/

#ifndef CRYPTO_SHIRE_H
#define CRYPTO_SHIRE_H

#include "crypto.h"
#include "sa_interface.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Which end of the link is calling; decides which SAs are advanced to be the sending side. */
#define CRYPTO_SHIRE_END_GROUND 0
#define CRYPTO_SHIRE_END_FLIGHT 1

#define CRYPTO_SHIRE_TC_VCID        0
#define CRYPTO_SHIRE_TC_CLEAR_SPI   1
#define CRYPTO_SHIRE_TC_SECURE_SPI  4
#define CRYPTO_SHIRE_TM_VCID        1
#define CRYPTO_SHIRE_TM_CLEAR_SPI   5
#define CRYPTO_SHIRE_TM_SECURE_SPI  6
#define CRYPTO_SHIRE_TM_KEY_ID      9 /* active key in the default in-memory key ring */
#define CRYPTO_SHIRE_GCM_IV_LEN     12
#define CRYPTO_SHIRE_GCM_MAC_LEN    16

/* Anti-replay window, in frames. A receiver only accepts an IV/ARSN at most this far ahead of the last
 * accepted one, so every frame lost on the link (radio drops, loss of signal) eats into it and a gap larger
 * than the window rejects all later frames. Replays are rejected regardless of the window size: it only
 * bounds how far ahead a frame may jump. The SDLS default of 5 would not survive a pass boundary. */
#define CRYPTO_SHIRE_ARSN_WINDOW    0xFFFF

    /* Big-endian counter increment (the same arithmetic CryptoLib uses for IV/ARSN), kept local so
     * this header only depends on the SADB interface. */
    static inline void Crypto_Shire_Increment(uint8_t *counter, int length)
    {
        for (int i = length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }

    /**
     * @brief Select clear or AES-256-GCM security associations for each link direction.
     *
     * Call after Crypto_SC_Init() (it must be called again after every re-initialization, which also
     * restarts the IV/ARSN counters at both ends, so re-initialize both ends together).
     * Flight software that builds a TM channel must call this before the channel is
     * initialized, because the channel reserves room for the SA's security header and trailer.
     *
     * @param end                CRYPTO_SHIRE_END_GROUND or CRYPTO_SHIRE_END_FLIGHT
     * @param uplink_encrypted   non-zero to encrypt and authenticate telecommands
     * @param downlink_encrypted non-zero to encrypt and authenticate telemetry
     * @return CRYPTO_LIB_SUCCESS, or CRYPTO_LIB_ERR_NO_INIT / CRYPTO_LIB_ERR_NULL_SA if the SADB is unavailable
     */
    static inline int32_t Crypto_Shire_Configure_Link_Security(uint8_t end, uint8_t uplink_encrypted,
                                                               uint8_t downlink_encrypted)
    {
        SaInterface            sadb   = get_sa_interface_inmemory();
        SecurityAssociation_t *clear  = NULL;
        SecurityAssociation_t *secure = NULL;
        int32_t                status;

        if (sadb == NULL || sadb->sa_get_from_spi == NULL)
        {
            return CRYPTO_LIB_ERR_NO_INIT;
        }

        /* Uplink: SPI 4 is predefined as AES-256-GCM encrypt + authenticate on TC VCID 0. */
        status = sadb->sa_get_from_spi(CRYPTO_SHIRE_TC_CLEAR_SPI, &clear);
        if (status == CRYPTO_LIB_SUCCESS)
        {
            status = sadb->sa_get_from_spi(CRYPTO_SHIRE_TC_SECURE_SPI, &secure);
        }
        if (status != CRYPTO_LIB_SUCCESS || clear == NULL || secure == NULL)
        {
            return CRYPTO_LIB_ERR_NULL_SA;
        }
        /* The predefined SA carries an ARSN that is not transmitted, and CryptoLib only advances the stored IV
         * when it can also validate an ARSN, so replays would never be caught. Protect with the IV alone. */
        secure->shsnf_len = 0;
        secure->arsn_len  = 0;
        secure->arsnw_len = 2;
        secure->arsnw     = CRYPTO_SHIRE_ARSN_WINDOW;
        clear->sa_state   = uplink_encrypted ? SA_NONE : SA_OPERATIONAL;
        secure->sa_state  = uplink_encrypted ? SA_OPERATIONAL : SA_NONE;
        if (end == CRYPTO_SHIRE_END_GROUND)
        {
            Crypto_Shire_Increment(secure->iv, secure->iv_len);
            Crypto_Shire_Increment(secure->arsn, secure->arsn_len);
        }

        /* Downlink: SPI 6 is repurposed from its predefined AES-CBC SA onto TM VCID 1. */
        clear  = NULL;
        secure = NULL;
        status = sadb->sa_get_from_spi(CRYPTO_SHIRE_TM_CLEAR_SPI, &clear);
        if (status == CRYPTO_LIB_SUCCESS)
        {
            status = sadb->sa_get_from_spi(CRYPTO_SHIRE_TM_SECURE_SPI, &secure);
        }
        if (status != CRYPTO_LIB_SUCCESS || clear == NULL || secure == NULL)
        {
            return CRYPTO_LIB_ERR_NULL_SA;
        }
        secure->ecs_len         = 1;
        secure->ecs             = CRYPTO_CIPHER_AES256_GCM;
        secure->acs_len         = 0;
        secure->est             = 1;
        secure->ast             = 1;
        secure->ekid            = CRYPTO_SHIRE_TM_KEY_ID;
        secure->akid            = CRYPTO_SHIRE_TM_KEY_ID;
        secure->null_iv         = 0;
        secure->shivf_len       = CRYPTO_SHIRE_GCM_IV_LEN;
        secure->iv_len          = CRYPTO_SHIRE_GCM_IV_LEN;
        secure->shsnf_len       = 0;
        secure->shplf_len       = 0;
        secure->arsn_len        = 0;
        secure->arsnw_len       = 2;
        secure->arsnw           = CRYPTO_SHIRE_ARSN_WINDOW;
        secure->stmacf_len      = CRYPTO_SHIRE_GCM_MAC_LEN;
        secure->abm_len         = ABM_SIZE;
        secure->gvcid_blk.tfvn  = 0;
        secure->gvcid_blk.scid  = clear->gvcid_blk.scid;
        secure->gvcid_blk.vcid  = CRYPTO_SHIRE_TM_VCID;
        secure->gvcid_blk.mapid = clear->gvcid_blk.mapid;
        memset(secure->abm, 0xFF, sizeof(secure->abm));

        clear->sa_state  = downlink_encrypted ? SA_NONE : SA_OPERATIONAL;
        secure->sa_state = downlink_encrypted ? SA_OPERATIONAL : SA_NONE;
        if (end == CRYPTO_SHIRE_END_FLIGHT)
        {
            Crypto_Shire_Increment(secure->iv, secure->iv_len);
            Crypto_Shire_Increment(secure->arsn, secure->arsn_len);
        }

        return CRYPTO_LIB_SUCCESS;
    }

#ifdef __cplusplus
} /* Close scope of 'extern "C"' declaration which encloses file. */
#endif

#endif /* CRYPTO_SHIRE_H */
