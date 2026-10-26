/**
 *  Unit tests for the SHIRE link-security configuration (include/crypto_shire.h).
 *
 *  Starts from Crypto_SC_Init() exactly as the ground standalone and the flight radio app do, selects the
 *  clear or encrypted security associations, and round-trips frames shaped like the ones SHIRE produces:
 *  TC on VCID 0 (segment header present, no FECF) and TM on VCID 1 (1786 byte frame, no FECF).
 **/
#include "crypto.h"
#include "crypto_shire.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "ut_shire_security.h"
#include "utest.h"

#define TEST_SCID        0x0003
#define TC_HEADER_LEN    5
#define TC_SEG_HDR_LEN   1
#define TM_FRAME_LEN     1786
#define TM_PRIMARY_LEN   6

static const uint8_t tc_payload[] = {0x18, 0xD2, 0xC0, 0x00, 0x00, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
static const uint8_t tm_payload[] = {0x08, 0x01, 0xC0, 0x00, 0x00, 0x0B, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
                                     0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x55, 0xAA};

/* The test plays both ends from one SADB. Configure as the sending end of the direction under test (ground
 * for TC, flight for TM); after "sending", rewind_to_receiver() leaves the SA as the receiving end has it. */
static int32_t shire_init(uint8_t end, uint8_t uplink_encrypted, uint8_t downlink_encrypted)
{
    remove("sa_save_file.bin");
    int32_t status = Crypto_SC_Init();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }
    return Crypto_Shire_Configure_Link_Security(end, uplink_encrypted, downlink_encrypted);
}

/* Leaves an SA the way the *receiving* end has it: a fresh IV/ARSN, one behind the sender's first frame. */
static void rewind_to_receiver(uint16_t spi)
{
    SecurityAssociation_t *sa = NULL;
    get_sa_interface_inmemory()->sa_get_from_spi(spi, &sa);
    memset(sa->iv, 0, sa->iv_len);
    memset(sa->arsn, 0, sa->arsn_len);
}

/* Builds a TC frame the way support/standalone does (dynamic length, segment header 0xC0). */
static uint16_t build_tc_frame(uint8_t *frame, uint8_t seq)
{
    uint16_t length = (uint16_t)(TC_HEADER_LEN + TC_SEG_HDR_LEN + sizeof(tc_payload));
    frame[0]        = 0x20;
    frame[1]        = TEST_SCID;
    frame[2]        = (uint8_t)(((CRYPTO_SHIRE_TC_VCID << 2) & 0xFC) | (((length - 1) >> 8) & 0x03));
    frame[3]        = (uint8_t)((length - 1) & 0xFF);
    frame[4]        = seq;
    frame[5]        = 0xC0;
    memcpy(&frame[6], tc_payload, sizeof(tc_payload));
    return length;
}

/* Builds a TM frame the way the flight TM SDLP does: payload follows the security header the SA reserves. */
static int32_t build_tm_frame(uint8_t *frame)
{
    SaInterface            sadb = get_sa_interface_inmemory();
    SecurityAssociation_t *sa   = NULL;
    memset(frame, 0, TM_FRAME_LEN);
    int32_t status = sadb->sa_get_operational_sa_from_gvcid(0, TEST_SCID, CRYPTO_SHIRE_TM_VCID, 0, &sa);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }
    uint16_t header_len = (uint16_t)Crypto_Get_Security_Header_Length(sa);

    frame[0] = 0x00;
    frame[1] = (uint8_t)((TEST_SCID << 4) | (CRYPTO_SHIRE_TM_VCID << 1));
    frame[4] = 0x18; /* no secondary header, packet data, first header pointer 0 */
    frame[5] = 0x00;
    memcpy(&frame[TM_PRIMARY_LEN + header_len], tm_payload, sizeof(tm_payload));
    return CRYPTO_LIB_SUCCESS;
}

static uint16_t tm_payload_offset(void)
{
    SaInterface            sadb = get_sa_interface_inmemory();
    SecurityAssociation_t *sa   = NULL;
    sadb->sa_get_operational_sa_from_gvcid(0, TEST_SCID, CRYPTO_SHIRE_TM_VCID, 0, &sa);
    return (uint16_t)(TM_PRIMARY_LEN + Crypto_Get_Security_Header_Length(sa));
}

/**
 * @brief Encrypted uplink: payload is not visible on the wire, SPI 4 is used, and the receiver recovers the payload.
 **/
UTEST(SHIRE_LINK_SECURITY, TC_ENCRYPTED_ROUND_TRIP)
{
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_GROUND, 1, 1));

    uint8_t  in[64];
    uint16_t in_len  = build_tc_frame(in, 0);
    uint8_t *out     = NULL;
    uint16_t out_len = 0;
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TC_ApplySecurity(in, in_len, &out, &out_len));
    rewind_to_receiver(CRYPTO_SHIRE_TC_SECURE_SPI);

    /* SDLS header (SPI 2 + IV 12 + ARSN) and MAC grow the frame; SPI 4 is on the wire. */
    ASSERT_TRUE(out_len > in_len + CRYPTO_SHIRE_GCM_MAC_LEN);
    ASSERT_EQ(0x00, out[6]);
    ASSERT_EQ(CRYPTO_SHIRE_TC_SECURE_SPI, out[7]);
    ASSERT_TRUE(memmem(out, out_len, tc_payload, sizeof(tc_payload)) == NULL);

    uint8_t frame[1024];
    memcpy(frame, out, out_len);
    int  len = out_len;
    TC_t tc;
    memset(&tc, 0, sizeof(tc));
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TC_ProcessSecurity(frame, &len, &tc));
    ASSERT_EQ((int)sizeof(tc_payload), (int)tc.tc_pdu_len);
    ASSERT_EQ(0, memcmp(tc.tc_pdu, tc_payload, sizeof(tc_payload)));

    Crypto_Shutdown();
}

/**
 * @brief A single flipped ciphertext bit must fail authentication.
 **/
UTEST(SHIRE_LINK_SECURITY, TC_TAMPERED_FRAME_REJECTED)
{
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_GROUND, 1, 1));

    uint8_t  in[64];
    uint16_t in_len  = build_tc_frame(in, 0);
    uint8_t *out     = NULL;
    uint16_t out_len = 0;
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TC_ApplySecurity(in, in_len, &out, &out_len));
    rewind_to_receiver(CRYPTO_SHIRE_TC_SECURE_SPI);

    uint8_t frame[1024];
    memcpy(frame, out, out_len);
    frame[TC_HEADER_LEN + TC_SEG_HDR_LEN + 2 + CRYPTO_SHIRE_GCM_IV_LEN + 11 + 3] ^= 0x01; /* inside the ciphertext */
    int  len = out_len;
    TC_t tc;
    memset(&tc, 0, sizeof(tc));
    ASSERT_NE(CRYPTO_LIB_SUCCESS, Crypto_TC_ProcessSecurity(frame, &len, &tc));

    Crypto_Shutdown();
}

/**
 * @brief A captured frame cannot be accepted twice.
 **/
UTEST(SHIRE_LINK_SECURITY, TC_REPLAYED_FRAME_REJECTED)
{
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_GROUND, 1, 1));

    uint8_t  in[64];
    uint16_t in_len  = build_tc_frame(in, 0);
    uint8_t *out     = NULL;
    uint16_t out_len = 0;
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TC_ApplySecurity(in, in_len, &out, &out_len));
    rewind_to_receiver(CRYPTO_SHIRE_TC_SECURE_SPI);

    uint8_t first[1024], second[1024];
    memcpy(first, out, out_len);
    memcpy(second, out, out_len);
    int  len = out_len;
    TC_t tc;
    memset(&tc, 0, sizeof(tc));
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TC_ProcessSecurity(first, &len, &tc));
    len = out_len;
    ASSERT_NE(CRYPTO_LIB_SUCCESS, Crypto_TC_ProcessSecurity(second, &len, &tc));

    Crypto_Shutdown();
}

/**
 * @brief With uplink encryption off the payload crosses in the clear (SPI 1) and still round-trips.
 **/
UTEST(SHIRE_LINK_SECURITY, TC_CLEAR_WHEN_UPLINK_ENCRYPTION_DISABLED)
{
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_GROUND, 0, 1));

    uint8_t  in[64];
    uint16_t in_len  = build_tc_frame(in, 0);
    uint8_t *out     = NULL;
    uint16_t out_len = 0;
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TC_ApplySecurity(in, in_len, &out, &out_len));
    rewind_to_receiver(CRYPTO_SHIRE_TC_SECURE_SPI);
    ASSERT_EQ(CRYPTO_SHIRE_TC_CLEAR_SPI, out[7]);
    ASSERT_TRUE(memmem(out, out_len, tc_payload, sizeof(tc_payload)) != NULL);

    uint8_t frame[1024];
    memcpy(frame, out, out_len);
    int  len = out_len;
    TC_t tc;
    memset(&tc, 0, sizeof(tc));
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TC_ProcessSecurity(frame, &len, &tc));
    ASSERT_EQ(0, memcmp(tc.tc_pdu, tc_payload, sizeof(tc_payload)));

    Crypto_Shutdown();
}

/**
 * @brief A receiver expecting encrypted uplink refuses a clear-mode frame.
 **/
UTEST(SHIRE_LINK_SECURITY, TC_CLEAR_FRAME_REJECTED_BY_ENCRYPTED_RECEIVER)
{
    /* Sender: encryption off. */
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_GROUND, 0, 0));
    uint8_t  in[64];
    uint16_t in_len  = build_tc_frame(in, 0);
    uint8_t *out     = NULL;
    uint16_t out_len = 0;
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TC_ApplySecurity(in, in_len, &out, &out_len));
    rewind_to_receiver(CRYPTO_SHIRE_TC_SECURE_SPI);
    uint8_t frame[1024];
    memcpy(frame, out, out_len);
    Crypto_Shutdown();

    /* Receiver: encryption on. */
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_FLIGHT, 1, 1));
    int  len = out_len;
    TC_t tc;
    memset(&tc, 0, sizeof(tc));
    ASSERT_NE(CRYPTO_LIB_SUCCESS, Crypto_TC_ProcessSecurity(frame, &len, &tc));

    Crypto_Shutdown();
}

/**
 * @brief Encrypted downlink round trip on TM VCID 1 using SPI 6.
 **/
UTEST(SHIRE_LINK_SECURITY, TM_ENCRYPTED_ROUND_TRIP)
{
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_FLIGHT, 1, 1));

    uint8_t frame[TM_FRAME_LEN];
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, build_tm_frame(frame));
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TM_ApplySecurity(frame, TM_FRAME_LEN));
    rewind_to_receiver(CRYPTO_SHIRE_TM_SECURE_SPI);

    ASSERT_EQ(0x00, frame[TM_PRIMARY_LEN]);
    ASSERT_EQ(CRYPTO_SHIRE_TM_SECURE_SPI, frame[TM_PRIMARY_LEN + 1]);
    ASSERT_TRUE(memmem(frame, TM_FRAME_LEN, tm_payload, sizeof(tm_payload)) == NULL);

    TM_t    *tm = malloc(TM_SIZE);
    uint16_t processed_len = 0;
    memset(tm, 0, TM_SIZE);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TM_ProcessSecurity(frame, TM_FRAME_LEN, tm, &processed_len));
    ASSERT_EQ(0, memcmp(tm->tm_pdu, tm_payload, sizeof(tm_payload)));
    free(tm);

    Crypto_Shutdown();
}

/**
 * @brief A flipped ciphertext bit in a downlink frame must fail authentication.
 **/
UTEST(SHIRE_LINK_SECURITY, TM_TAMPERED_FRAME_REJECTED)
{
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_FLIGHT, 1, 1));

    uint8_t frame[TM_FRAME_LEN];
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, build_tm_frame(frame));
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TM_ApplySecurity(frame, TM_FRAME_LEN));
    rewind_to_receiver(CRYPTO_SHIRE_TM_SECURE_SPI);
    frame[tm_payload_offset() + 4] ^= 0x01;

    TM_t    *tm = malloc(TM_SIZE);
    uint16_t processed_len = 0;
    memset(tm, 0, TM_SIZE);
    ASSERT_NE(CRYPTO_LIB_SUCCESS, Crypto_TM_ProcessSecurity(frame, TM_FRAME_LEN, tm, &processed_len));
    free(tm);

    Crypto_Shutdown();
}

/**
 * @brief A captured downlink frame cannot be accepted twice.
 **/
UTEST(SHIRE_LINK_SECURITY, TM_REPLAYED_FRAME_REJECTED)
{
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_FLIGHT, 1, 1));

    uint8_t frame[TM_FRAME_LEN], again[TM_FRAME_LEN];
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, build_tm_frame(frame));
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TM_ApplySecurity(frame, TM_FRAME_LEN));
    rewind_to_receiver(CRYPTO_SHIRE_TM_SECURE_SPI);
    memcpy(again, frame, TM_FRAME_LEN);

    TM_t    *tm = malloc(TM_SIZE);
    uint16_t processed_len = 0;
    memset(tm, 0, TM_SIZE);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TM_ProcessSecurity(frame, TM_FRAME_LEN, tm, &processed_len));
    ASSERT_NE(CRYPTO_LIB_SUCCESS, Crypto_TM_ProcessSecurity(again, TM_FRAME_LEN, tm, &processed_len));
    free(tm);

    Crypto_Shutdown();
}

/**
 * @brief Frames lost on the link (a whole pass worth) do not desynchronize the receiver.
 **/
UTEST(SHIRE_LINK_SECURITY, TM_FRAMES_AFTER_A_LONG_GAP_ARE_ACCEPTED)
{
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_FLIGHT, 1, 1));

    uint8_t frame[TM_FRAME_LEN];
    for (int lost = 0; lost < 2000; lost++)
    {
        ASSERT_EQ(CRYPTO_LIB_SUCCESS, build_tm_frame(frame));
        ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TM_ApplySecurity(frame, TM_FRAME_LEN)); /* never delivered */
    }
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, build_tm_frame(frame));
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TM_ApplySecurity(frame, TM_FRAME_LEN));
    rewind_to_receiver(CRYPTO_SHIRE_TM_SECURE_SPI);

    TM_t    *tm = malloc(TM_SIZE);
    uint16_t processed_len = 0;
    memset(tm, 0, TM_SIZE);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TM_ProcessSecurity(frame, TM_FRAME_LEN, tm, &processed_len));
    ASSERT_EQ(0, memcmp(tm->tm_pdu, tm_payload, sizeof(tm_payload)));
    free(tm);

    Crypto_Shutdown();
}

/**
 * @brief With downlink encryption off, telemetry is in the clear (SPI 5) and still round-trips.
 **/
UTEST(SHIRE_LINK_SECURITY, TM_CLEAR_WHEN_DOWNLINK_ENCRYPTION_DISABLED)
{
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_FLIGHT, 1, 0));

    uint8_t frame[TM_FRAME_LEN];
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, build_tm_frame(frame));
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TM_ApplySecurity(frame, TM_FRAME_LEN));
    rewind_to_receiver(CRYPTO_SHIRE_TM_SECURE_SPI);
    ASSERT_EQ(CRYPTO_SHIRE_TM_CLEAR_SPI, frame[TM_PRIMARY_LEN + 1]);
    ASSERT_TRUE(memmem(frame, TM_FRAME_LEN, tm_payload, sizeof(tm_payload)) != NULL);

    TM_t    *tm = malloc(TM_SIZE);
    uint16_t processed_len = 0;
    memset(tm, 0, TM_SIZE);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_TM_ProcessSecurity(frame, TM_FRAME_LEN, tm, &processed_len));
    ASSERT_EQ(0, memcmp(tm->tm_pdu, tm_payload, sizeof(tm_payload)));
    free(tm);

    Crypto_Shutdown();
}

/**
 * @brief Re-applying the configuration is idempotent and the two directions are independent.
 **/
UTEST(SHIRE_LINK_SECURITY, DIRECTIONS_ARE_INDEPENDENT_AND_REAPPLYING_IS_SAFE)
{
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, shire_init(CRYPTO_SHIRE_END_FLIGHT, 1, 0));
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_Shire_Configure_Link_Security(CRYPTO_SHIRE_END_FLIGHT, 1, 0));

    SaInterface            sadb = get_sa_interface_inmemory();
    SecurityAssociation_t *sa   = NULL;
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, sadb->sa_get_operational_sa_from_gvcid(0, TEST_SCID, CRYPTO_SHIRE_TC_VCID, 0, &sa));
    ASSERT_EQ(CRYPTO_SHIRE_TC_SECURE_SPI, sa->spi);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, sadb->sa_get_operational_sa_from_gvcid(0, TEST_SCID, CRYPTO_SHIRE_TM_VCID, 0, &sa));
    ASSERT_EQ(CRYPTO_SHIRE_TM_CLEAR_SPI, sa->spi);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, Crypto_Shire_Configure_Link_Security(CRYPTO_SHIRE_END_FLIGHT, 0, 1));
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, sadb->sa_get_operational_sa_from_gvcid(0, TEST_SCID, CRYPTO_SHIRE_TC_VCID, 0, &sa));
    ASSERT_EQ(CRYPTO_SHIRE_TC_CLEAR_SPI, sa->spi);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, sadb->sa_get_operational_sa_from_gvcid(0, TEST_SCID, CRYPTO_SHIRE_TM_VCID, 0, &sa));
    ASSERT_EQ(CRYPTO_SHIRE_TM_SECURE_SPI, sa->spi);

    Crypto_Shutdown();
}

UTEST_MAIN();
