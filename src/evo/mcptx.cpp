// Copyright (c) 2018-2025 Thought Network Ltd
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "deterministicmns.h"
#include "specialtx.h"
#include "mcptx.h"

#include "base58.h"
#include "chainparams.h"
#include "clientversion.h"
#include "core_io.h"
#include "hash.h"
#include "messagesigner.h"
#include "script/standard.h"
#include "streams.h"
#include "univalue.h"
#include "validation.h"

#include <boost/url/urls.hpp>

template <typename McpTx>
static bool CheckService(const uint256& mcpTxHash, const McpTx& mcpTx, CValidationState& state)
{
    if (!mcpTx.ipAddress.IsValid()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-mcptx-ipaddr");
    }
    if (Params().RequireRoutableExternalIP() && !mcpTx.ipAddress.IsRoutable()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-mcptx-ipaddr");
    }

    static int mainnetDefaultPort = CreateChainParams(CBaseChainParams::MAIN)->GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (mcpTx.ipAddress.GetPort() != mainnetDefaultPort) {
            return state.DoS(10, false, REJECT_INVALID, "bad-mcptx-ipaddr-port");
        }
    } else if (mcpTx.ipAddress.GetPort() == mainnetDefaultPort) {
        return state.DoS(10, false, REJECT_INVALID, "bad-mcptx-ipaddr-port");
    }

    if (!mcpTx.ipAddress.IsIPv4() && !mcpTx.ipAddress.IsIPv6()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-mcptx-ipaddr");
    }

    return true;
}

template <typename McpTx>
static bool CheckHashSig(const McpTx& mcpTx, const CKeyID& keyID, CValidationState& state)
{
    std::string strError;
    if (!CHashSigner::VerifyHash(::SerializeHash(mcpTx), keyID, mcpTx.vchSig, strError)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-sig", false, strError);
    }
    return true;
}

template <typename McpTx>
static bool CheckStringSig(const McpTx& mcpTx, const CKeyID& keyID, CValidationState& state)
{
    std::string strError;
    if (!CMessageSigner::VerifyMessage(keyID, mcpTx.vchSig, mcpTx.MakeSignString(), strError)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-sig", false, strError);
    }
    return true;
}

template <typename McpTx>
static bool CheckHashSig(const McpTx& mcpTx, const CBLSPublicKey& pubKey, CValidationState& state)
{
    if (!mcpTx.sig.VerifyInsecure(pubKey, ::SerializeHash(mcpTx))) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-sig", false);
    }
    return true;
}

template <typename McpTx>
static bool CheckInputsHash(const CTransaction& tx, const McpTx& mcpTx, CValidationState& state)
{
    uint256 inputsHash = CalcTxInputsHash(tx);
    if (inputsHash != mcpTx.inputsHash) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-inputs-hash");
    }

    return true;
}

bool CheckMcpRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    // Check tx type
    if (tx.nType != TRANSACTION_MCP_REGISTER) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-type");
    }

    // Check tx payload, version, type, mode, keyIDOwner, pubKeyOperator, keyIDVoting, scriptPayout
    CMcpRegTx mcptx;
    if (!GetTxPayload(tx, mcptx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-payload");
    }

    // version check
    if (mcptx.version == 0 || mcptx.version > CMcpRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-version");
    }



    // need to check

    // // TxCore Fields
    // CNetAddr ipAddress;
    // boost::uuids::uuid mcpId;
    // uint16_t version;
    // std::vector<unsigned char> name; // string
    // std::vector<unsigned char> mcpId; // URI conflicting

    return true;
}

bool CheckMcpUnregTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_MCP_UNREGISTER) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-type");
    }

    CMcpUnregTx mcptx;
    if (!GetTxPayload(tx, mcptx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-payload");
    }

    if (mcptx.version == 0 || mcptx.version > CMcpRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-version");
    }

    // need to check

    // // TxCore Fields
    // CNetAddr ipAddress;
    // boost::uuids::uuid mcpId; // UUID
    // uint16_t version;    
    // std::vector<unsigned char> mcpId; // URI
    // std::vector<unsigned char> action; // enum
    // std::vector<unsigned char> postAction; // enum

    return true;
}

bool CheckMcpXferTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_MCP_TRANSFER) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-type");
    }

    CMcpXferTx mcptx;
    if (!GetTxPayload(tx, mcptx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-payload");
    }

    if (mcptx.version == 0 || mcptx.version > CMcpRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-version");
    }

    // need to check

    // // TxCore Fields
    // CNetAddr ipAddress;
    // boost::uuids::uuid mcpId;
    // uint16_t version;    
    // std::vector<unsigned char> nuanceId; // URI
    // uint256 toWallet; // address/hash

    return true;
}

bool CheckMcpAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_MCP_AUTHORIZE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-type");
    }

    CMcpAuthTx mcptx;
    if (!GetTxPayload(tx, mcptx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-payload");
    }

    if (mcptx.version == 0 || mcptx.version > CMcpRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-version");
    }

    // need to check

    // // TxCore Fields
    // CNetAddr ipAddress;
    // boost::uuids::uuid mcpId;
    // uint16_t version;    
    // std::vector<unsigned char> nuanceId; // URI
    // uint256 authorizeWallet; // address/hash

    return true;
}

bool CheckMcpRevAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_MCP_REVOKE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-type");
    }

    CMcpAuthTx mcptx;
    if (!GetTxPayload(tx, mcptx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-payload");
    }

    if (mcptx.version == 0 || mcptx.version > CMcpRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-version");
    }

    // need to check

    // // TxCore Fields
    // CNetAddr ipAddress;
    // boost::uuids::uuid mcpId;
    // uint16_t version;    
    // std::vector<unsigned char> nuanceId; // URI
    // uint256 revokeWallet; // address/hash

    return true;
}


bool CheckMcpCheckTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_MCP_CHECK) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-type");
    }

    CMcpAuthTx mcptx;
    if (!GetTxPayload(tx, mcptx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-payload");
    }

    if (mcptx.version == 0 || mcptx.version > CMcpRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mcptx-version");
    }

    // need to check

    // // TxCore Fields
    // CNetAddr ipAddress;
    // boost::uuids::uuid mcpId;
    // uint16_t version;    
    // std::vector<unsigned char> nuanceId; // txid - hash
    // uint256 hash; // hash of concept
    // bool nuanceSatisfied; // bool

    return true;
}


std::string CMcpRegTx::ToString() const
{
    return strprintf("CMcpRegTx(ipAddress=%d, mcpId=%s, version=%d, name=%s)",
        ipAddress, mcpId.ToString(), version, name);
}

std::string CMcpUnregTx::ToString() const
{
    return strprintf("CMcpUnregTx(ipAddress=%d, mcpId=%s, version=%d, action=%s, postAction=%s)",
        ipAddress, mcpId.ToString(), version, action, postAction);
}

std::string CMcpXferTx::ToString() const
{
    return strprintf("CMcpXferTx(ipAddress=%d, mcpId=%s, version=%d, nuanceId=%s, toWallet=%s)",
        ipAddress, mcpId.ToString(), version, nuanceId, toWallet);
}

std::string CMcpAuthTx::ToString() const
{
    return strprintf("CMcpAuthTx(ipAddress=%d, mcpId=%s, version=%d, nuanceId=%s, authorizeWallet=%s)",
        ipAddress, mcpId.ToString(), version, nuanceId, authorizeWallet);
}

std::string CMcpRevAuthTx::ToString() const
{
    return strprintf("CMcpRevAuthTx(ipAddress=%d, mcpId=%s, version=%d, nuanceId=%s, revokeWallet=%s)",
        ipAddress, mcpId.ToString(), version, nuanceId, revokeWallet);
}

std::string CMcpCheckTx::ToString() const
{
    return strprintf("CMcpCheckTx(ipAddress=%d, mcpId=%s, version=%d, nuanceId=%s, hash=%s, nuanceSatisfied=%s)",
        ipAddress, mcpId.ToString(), version, nuanceId, hash, nuanceSatisfied);
}

void CMcpRegTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("name", name));
}

void CMcpUnregTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("action", action));
    obj.push_back(Pair("postAction", postAction));
}

void CMcpXferTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("nuanceId", nuanceId));
    obj.push_back(Pair("toWallet", toWallet));
}

void CMcpAuthTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("nuanceId", nuanceId));
    obj.push_back(Pair("authorizeWallet", authorizeWallet));
}

void CMcpRevAuthTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("nuanceId", nuanceId));
    obj.push_back(Pair("revokeWallet", revokeWallet));
}

void CMcpCheckTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("nuanceId", nuanceId));
    obj.push_back(Pair("hash", hash));
    obj.push_back(Pair("nuanceSatisfied", nuanceSatisfied));

}