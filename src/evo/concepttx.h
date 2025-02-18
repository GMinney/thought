// Copyright (c) 2018-2025 Thought Network Ltd
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef THOUGHT_EVO_CONCEPTTX_H
#define THOUGHT_EVO_CONCEPTTX_H

#include <bls/bls.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>

#include <netaddress.h>
#include <pubkey.h>
#include <univalue.h>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.

class CBlockIndex;
class CCoinsViewCache;

// Create/Register concept
class CConRegTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept Registration Fields
    CNetAddr ipAddress;
    boost::uuids::uuid mcpId;
    uint16_t version;
    std::vector<unsigned char> name; //string
    uint256 conceptId; // txid - hash
    uint256 conceptHash; // hash of concept
    std::vector<unsigned char> conceptParentId; // URI
    std::vector<unsigned char> conceptVersion; // String
    std::vector<unsigned char> codeLocation; // URI

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(name);
        READWRITE(conceptId);
        READWRITE(conceptHash);
        READWRITE(conceptParentId);
        READWRITE(conceptVersion);
        READWRITE(codeLocation);
    }

    // When signing with the collateral key, we don't sign the hash but a generated message instead
    // This is needed for HW wallet support which can only sign text messages as of now
    std::string MakeSignString() const;

    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

// Update concept
class CConUpTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept Update Fields
    uint256 conceptId; // txid - hash
    uint256 conceptHash; // hash of concept
    std::vector<unsigned char> conceptVersion; // String
    std::vector<unsigned char> codeLocation; // URI

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(conceptId);
        READWRITE(conceptHash);
        READWRITE(conceptVersion);
        READWRITE(codeLocation);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

// Remove/Unregister concept 
class CConUnregTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept un-register Fields
    uint256 conceptId; // txid - hash
    std::vector<unsigned char> version; // String
    std::vector<unsigned char> action; // enum

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(conceptId);
        READWRITE(version);
        READWRITE(action);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

// Transfer concept ownership
class CConXferTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept transfer Fields
    uint256 conceptId; // URI
    uint256 toWallet; // hash of concept
    std::vector<unsigned char> version; // String

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(conceptId);
        READWRITE(toWallet);
        READWRITE(version);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

// Authorize concept user
class CConAuthTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept user authorization Fields
    uint256 conceptId; // txid - hash
    uint256 authorizeWallet; // hash of concept
    std::vector<unsigned char> version; // String

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(conceptId);
        READWRITE(authorizeWallet);
        READWRITE(version);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

// Revoke concept authorization
class CConRevAuthTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // Concept revoke authorization Fields
    uint256 conceptId; // txid - hash
    uint256 revokeWallet; // hash of concept
    std::vector<unsigned char> version; // String

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(conceptId);
        READWRITE(revokeWallet);
        READWRITE(version);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

bool CheckConRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckConUpTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckConUnregTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckConXferTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckConAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckConRevAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);

#endif // THOUGHT_EVO_CONCEPTTX_H