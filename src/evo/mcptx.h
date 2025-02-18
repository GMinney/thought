// Copyright (c) 2018-2025 Thought Network Ltd
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef THOUGHT_EVO_MCPTX_H
#define THOUGHT_EVO_MCPTX_H

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

// Register MCP 
class CMcpRegTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // MCP Registration Fields
    CNetAddr ipAddress;
    std::vector<unsigned char> mcpId; // URI 
    uint16_t version;
    std::vector<unsigned char> name; // string

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(name);
    }

    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

// Unregister MCP 
class CMcpUnregTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // MCP Unregister Fields
    CNetAddr ipAddress;
    uint16_t version;    
    std::vector<unsigned char> mcpId; // URI
    std::vector<unsigned char> action; // enum
    std::vector<unsigned char> postAction; // enum

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId); // conflict
        READWRITE(mcpId); // conflict
        READWRITE(action);
        READWRITE(postAction);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

// Transfer MCP ownership
class CMcpXferTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // MCP Transfer Fields
    CNetAddr ipAddress;
    std::vector<unsigned char> mcpId; // URI
    uint16_t version;    
    std::vector<unsigned char> nuanceId; // URI
    uint256 toWallet; // address/hash


public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(nuanceId);
        READWRITE(toWallet);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

// Authorize MCP user
class CMcpAuthTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // MCP Authorization Fields
    CNetAddr ipAddress;
    std::vector<unsigned char> mcpId; // URI
    uint16_t version;    
    std::vector<unsigned char> nuanceId; // URI
    uint256 authorizeWallet; // address/hash


public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(nuanceId);
        READWRITE(authorizeWallet);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

// Revoke authorization
class CMcpCheckTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // MCP Checkpoint Fields
    CNetAddr ipAddress;
    std::vector<unsigned char> mcpId; // URI
    uint16_t version;    
    std::vector<unsigned char> nuanceId; // txid - hash
    uint256 hash; // hash of concept
    bool nuanceSatisfied; // bool

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(nuanceId);
        READWRITE(hash);
        READWRITE(nuanceSatisfied);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

// Revoke authorization
class CMcpRevAuthTx
{
public:
    static const uint16_t CURRENT_VERSION = 1;

public:
    // MCP Revoke Auth Fields
    CNetAddr ipAddress;
    std::vector<unsigned char> mcpId; // URI
    uint16_t version;    
    std::vector<unsigned char> nuanceId; // URI
    uint256 revokeWallet; // address/hash

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ipAddress);
        READWRITE(mcpId);
        READWRITE(version);
        READWRITE(nuanceId);
        READWRITE(revokeWallet);
    }

public:
    std::string ToString() const;

    void ToJson(UniValue& obj) const;
};

bool CheckMcpRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckMcpUnregTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckMcpXferTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckMcpAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckMcpRevAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
bool CheckMcpCheckTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);

#endif // THOUGHT_EVO_MCPTX_H