/*
 * This file is part of the TrinityCore Project. See AUTHORS file for Copyright information
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __AUTHSESSION_H__
#define __AUTHSESSION_H__

#include "AsyncCallbackProcessor.h"
#include "BigNumber.h"
#include "ByteBuffer.h"
#include "Common.h"
#include "CryptoHash.h"
#include "Optional.h"
#include "Socket.h"
#include "SRP6.h"
#include "QueryResult.h"
#include <memory>
#include <boost/asio/ip/tcp.hpp>
#include <openssl/md5.h>
#include "Patcher.h"

using boost::asio::ip::tcp;

class Field;
struct AuthHandler;

enum AuthStatus
{
    STATUS_CHALLENGE = 0,
    STATUS_LOGON_PROOF,
    STATUS_RECONNECT_PROOF,
    STATUS_AUTHED,
    STATUS_WAITING_FOR_REALM_LIST,
    STATUS_CLOSED
};

enum eAuthCmd
{
    AUTH_LOGON_CHALLENGE = 0x00,
    AUTH_LOGON_PROOF = 0x01,
    AUTH_RECONNECT_CHALLENGE = 0x02,
    AUTH_RECONNECT_PROOF = 0x03,
    REALM_LIST = 0x10,
    XFER_INITIATE = 0x30,
    XFER_DATA = 0x31,
    XFER_ACCEPT = 0x32,
    XFER_RESUME = 0x33,
    XFER_CANCEL = 0x34
};

#pragma pack(push, 1)

typedef struct AUTH_LOGON_CHALLENGE_C
{
    uint8   cmd;
    uint8   error;
    uint16  size;
    uint8   gamename[4];
    uint8   version1;
    uint8   version2;
    uint8   version3;
    uint16  build;
    uint8   platform[4];
    uint8   os[4];
    uint8   country[4];
    uint32  timezone_bias;
    uint32  ip;
    uint8   I_len;
    uint8   I[1];
} sAuthLogonChallenge_C;

typedef struct AUTH_LOGON_PROOF_C
{
    uint8   cmd;
    uint8   A[32];
    uint8   M1[20];
    uint8   crc_hash[20];
    uint8   number_of_keys;
    uint8   securityFlags;
} sAuthLogonProof_C;

typedef struct AUTH_LOGON_PROOF_S
{
    uint8   cmd;
    uint8   error;
    uint8   M2[20];
    uint32  AccountFlags;
    uint32  SurveyId;
    uint16  LoginFlags;
} sAuthLogonProof_S;

typedef struct AUTH_LOGON_PROOF_S_OLD
{
    uint8   cmd;
    uint8   error;
    uint8   M2[20];
    uint32  unk2;
} sAuthLogonProof_S_Old;

typedef struct AUTH_RECONNECT_PROOF_C
{
    uint8   cmd;
    uint8   R1[16];
    uint8   R2[20];
    uint8   R3[20];
    uint8   number_of_keys;
} sAuthReconnectProof_C;

typedef struct XFER_INIT_C {
    uint8 cmd;
    uint8 nameLength;
    uint8 fileName[5];
    uint64 fileSize;
    uint8 MD5[MD5_DIGEST_LENGTH];
} sXferInit_C;

typedef struct XFER_RESUME_C {
    uint8 cmd;
    uint64 pos;
} sXferResume_C;;

typedef struct XFER_RESUME_S {
    uint8 cmd;
    uint64 pos;
} sXferResume_S;

struct TransferDataPacket {
    uint8 cmd;
    uint16 chunk_size;
};

#pragma pack(pop)

struct AccountInfo
{
    void LoadResult(Field* fields);

    uint32 Id = 0;
    std::string Login;
    bool IsLockedToIP = false;
    std::string LockCountry;
    std::string LastIP;
    uint32 FailedLogins = 0;
    bool IsBanned = false;
    bool IsPermanenetlyBanned = false;
    AccountTypes SecurityLevel = SEC_PLAYER;
};

class AuthSession : public Socket<AuthSession>
{
    typedef Socket<AuthSession> AuthSocket;

public:
    static std::unordered_map<uint8, AuthHandler> InitHandlers();

    AuthSession(tcp::socket&& socket);
    ~AuthSession();

    void Start() override;
    bool Update() override;

    void SendPacket(ByteBuffer& packet);

    Patcher* _patcher;
protected:
    void ReadHandler() override;

private:
    bool HandleLogonChallenge();
    bool HandleLogonProof();
    bool HandleReconnectChallenge();
    bool HandleReconnectProof();
    bool HandleRealmList();

    //data transfer handle for patch
    bool HandleXferResume();
    bool HandleXferCancel();
    bool HandleXferAccept();

    void CheckIpCallback(PreparedQueryResult result);
    void LogonChallengeCallback(PreparedQueryResult result);
    void ReconnectChallengeCallback(PreparedQueryResult result);
    void RealmListCallback(PreparedQueryResult result);

    bool VerifyVersion(uint8 const* a, int32 aLength, Trinity::Crypto::SHA1::Digest const& versionProof, bool isReconnect);

    Optional<Trinity::Crypto::SRP6> _srp6;
    SessionKey _sessionKey = {};
    std::array<uint8, 16> _reconnectProof = {};

    AuthStatus _status;
    AccountInfo _accountInfo;
    Optional<std::vector<uint8>> _totpSecret;
    std::string _localizationName;
    std::string _os;
    std::string _ipCountry;
    uint16 _build;
    uint8 _expversion;

    QueryCallbackProcessor _queryProcessor;
};

#pragma pack(push, 1)

struct AuthHandler
{
    AuthStatus status;
    size_t packetSize;
    bool (AuthSession::*handler)();
};

#pragma pack(pop)

#endif
