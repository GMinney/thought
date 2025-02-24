// Copyright (c) 2018-2025 Thought Network Ltd
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "deterministicmns.h"
#include "specialtx.h"
#include "nuancetx.h"

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

template <typename NuanceTx>
static bool CheckService(const uint256& nuanceTxHash, const NuanceTx& nuanceTx, CValidationState& state)
{
    if (!nuanceTx.ipAddress.IsValid()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ipaddr");
    }
    if (Params().RequireRoutableExternalIP() && !nuanceTx.ipAddress.IsRoutable()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ipaddr");
    }

    static int mainnetDefaultPort = CreateChainParams(CBaseChainParams::MAIN)->GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (nuanceTx.ipAddress.GetPort() != mainnetDefaultPort) {
            return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ipaddr-port");
        }
    } else if (nuanceTx.ipAddress.GetPort() == mainnetDefaultPort) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ipaddr-port");
    }

    if (!nuanceTx.ipAddress.IsIPv4() && !nuanceTx.ipAddress.IsIPv6()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ipaddr");
    }

    return true;
}

template <typename NuanceTx>
static bool CheckHashSig(const NuanceTx& nuanceTx, const CKeyID& keyID, CValidationState& state)
{
    std::string strError;
    if (!CHashSigner::VerifyHash(::SerializeHash(nuanceTx), keyID, nuanceTx.vchSig, strError)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-sig", false, strError);
    }
    return true;
}

template <typename NuanceTx>
static bool CheckStringSig(const NuanceTx& nuanceTx, const CKeyID& keyID, CValidationState& state)
{
    std::string strError;
    if (!CMessageSigner::VerifyMessage(keyID, nuanceTx.vchSig, nuanceTx.MakeSignString(), strError)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-sig", false, strError);
    }
    return true;
}

template <typename NuanceTx>
static bool CheckHashSig(const NuanceTx& nuanceTx, const CBLSPublicKey& pubKey, CValidationState& state)
{
    if (!nuanceTx.sig.VerifyInsecure(pubKey, ::SerializeHash(nuanceTx))) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-sig", false);
    }
    return true;
}

template <typename NuanceTx>
static bool CheckInputsHash(const CTransaction& tx, const NuanceTx& nuanceTx, CValidationState& state)
{
    uint256 inputsHash = CalcTxInputsHash(tx);
    if (inputsHash != nuanceTx.inputsHash) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-inputs-hash");
    }

    return true;
}

bool CheckNuRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_NUANCE_REGISTER) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-type");
    }

    CNuRegTx ntx;
    if (!GetTxPayload(tx, ntx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-payload");
    }

    if (ntx.version == 0 || ntx.version > CNuRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    return true;
}

bool CheckNuUnregTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_NUANCE_UNREGISTER) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-type");
    }

    CNuUnregTx ntx;
    if (!GetTxPayload(tx, ntx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-payload");
    }

    if (ntx.version == 0 || ntx.version > CNuRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    return true;
}

bool CheckNuXferTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_NUANCE_TRANSFER) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-type");
    }

    CNuXferTx ntx;
    if (!GetTxPayload(tx, ntx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-payload");
    }

    if (ntx.version == 0 || ntx.version > CNuRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    return true;
}

bool CheckNuRevAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_NUANCE_REVOKE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-type");
    }

    CNuRevAuthTx ntx;
    if (!GetTxPayload(tx, ntx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-payload");
    }

    if (ntx.version == 0 || ntx.version > CNuRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    return true;
}

bool CheckNuAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_NUANCE_AUTHORIZE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-type");
    }

    CNuAuthTx ntx;
    if (!GetTxPayload(tx, ntx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-payload");
    }

    if (ntx.version == 0 || ntx.version > CNuRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    return true;
}

bool CheckNuCheckTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_NUANCE_CHECKPOINT) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-type");
    }

    CNuCheckTx ntx;
    if (!GetTxPayload(tx, ntx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-payload");
    }

    if (ntx.version == 0 || ntx.version > CNuRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    return true;
}


std::string CNuRegTx::ToString() const
{
    return strprintf("CNuRegTx(ipAddress=%s, mcpId=%s, version=%d, name=%s, conceptId=%s, hash=%s)",
        ipAddress, mcpId.ToString(), version, name, conceptId, hash);
}

std::string CNuUnregTx::ToString() const
{
    return strprintf("CNuUnregTx(ipAddress=%s, mcpId=%s, version=%d, nuanceId=%s, action=%s, postAction=%s)",
        ipAddress, mcpId.ToString(), version, nuanceId, action, postAction);
}

std::string CNuXferTx::ToString() const
{
    return strprintf("CNuXferTx(ipAddress=%s, mcpId=%s, version=%d, nuanceId=%s, toWallet=%s)",
        ipAddress, mcpId.ToString(), version, nuanceId, toWallet);
}

std::string CNuCheckTx::ToString() const
{
    return strprintf("CNuCheckTx(ipAddress=%s, mcpId=%s, version=%d, nuanceId=%s, hash=%s, nuanceSatisfied=%s)",
        ipAddress, mcpId.ToString(), version, nuanceId, hash, nuanceSatisfied);
}

std::string CNuAuthTx::ToString() const
{
    return strprintf("CNuAuthTx(ipAddress=%s, mcpId=%s, version=%d, nuanceId=%s, authorizeWallet=%s)",
        ipAddress, mcpId.ToString(), version, nuanceId, authorizeWallet);
}

std::string CNuRevAuthTx::ToString() const
{
    return strprintf("CNuRevAuthTx(ipAddress=%s, mcpId=%s, version=%d, nuanceId=%s, revokeWallet=%s)",
        ipAddress, mcpId.ToString(), version, nuanceId, revokeWallet);
}

void CNuRegTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("name", name));
    obj.push_back(Pair("conceptId", conceptId));
    obj.push_back(Pair("hash", hash));
}

void CNuUnregTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("nuanceId", nuanceId));
    obj.push_back(Pair("action", action));
    obj.push_back(Pair("postAction", postAction));
}

void CNuXferTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("nuanceId", nuanceId));
    obj.push_back(Pair("toWallet", toWallet));
}

void CNuCheckTx::ToJson(UniValue& obj) const
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

void CNuAuthTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("nuanceId", nuanceId));
    obj.push_back(Pair("authorizeWallet", authorizeWallet));
}

void CNuRevAuthTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("nuanceId", nuanceId));
    obj.push_back(Pair("revokeWallet", revokeWallet));
}