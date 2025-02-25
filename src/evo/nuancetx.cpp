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

#include <regex>

#include <boost/url/urls.hpp>
#include <boost/url/parse.hpp>
using namespace boost::urls;

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
    // payload check
    if (!GetTxPayload(tx, ntx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-payload");
    }

    // ipAddress check
    if (!ntx.ipAddress.IsIPv4() || !ntx.ipAddress.IsIPv6()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ip-invalid");
    }

    // mcpid uri check
    boost::system::result<url_view> mcpUri = parse_uri( ntx.mcpId );
    if (ntx.mcpId.length() == 0 || mcpUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-mcpId-invalid");
    }

    // version check
    if (ntx.version == 0 || ntx.version > CNuRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    // name check
    if (ntx.name.size() == 0) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-name");
    }

    // conceptId uri check
    boost::system::result<url_view> conceptUri = parse_uri( ntx.conceptId );
    if (ntx.conceptId.length() == 0 || conceptUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-conceptId-invalid");
    }

    // hash check - would require the retreval of the concept, then validating it


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

    // ipAddress check
    if (!ntx.ipAddress.IsIPv4() || !ntx.ipAddress.IsIPv6()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ip-invalid");
    }

    // uri check for mcpid
    boost::system::result<url_view> mcpUri = parse_uri( ntx.mcpId );
    if (ntx.mcpId.length() == 0 || mcpUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-mcpId-invalid");
    }

    // version check
    if (ntx.version == 0 || ntx.version > CNuUnregTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    // uri check for nuanceId
    boost::system::result<url_view> nuanceUri = parse_uri( ntx.nuanceId );
    if (ntx.nuanceId.length() == 0 || nuanceUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-nuanceId-invalid");
    }

    // action check

    // postAction check

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

    // ipAddress check
    if (!ntx.ipAddress.IsIPv4() || !ntx.ipAddress.IsIPv6()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ip-invalid");
    }

    // uri check for mcpid
    boost::system::result<url_view> mcpUri = parse_uri( ntx.mcpId );
    if (ntx.mcpId.length() == 0 || mcpUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-mcpId-invalid");
    }

    // version check
    if (ntx.version == 0 || ntx.version > CNuAuthTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    // uri check for nuanceId
    boost::system::result<url_view> conceptUri = parse_uri( ntx.nuanceId );
    if (ntx.nuanceId.length() == 0 || conceptUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-conceptId-invalid");
    }

    // authorizeWallet check 

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

    // ipAddress check
    if (!ntx.ipAddress.IsIPv4() || !ntx.ipAddress.IsIPv6()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ip-invalid");
    }

    // uri check for mcpid
    boost::system::result<url_view> mcpUri = parse_uri( ntx.mcpId );
    if (ntx.mcpId.length() == 0 || mcpUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-mcpId-invalid");
    }

    // version check
    if (ntx.version == 0 || ntx.version > CNuRevAuthTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    // uri check for nuanceId
    boost::system::result<url_view> nuanceUri = parse_uri( ntx.nuanceId );
    if (ntx.nuanceId.length() == 0 || nuanceUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-nuanceId-invalid");
    }

    // revokeWallet check

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

    // ipAddress check
    if (!ntx.ipAddress.IsIPv4() || !ntx.ipAddress.IsIPv6()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ip-invalid");
    }

    // uri check for mcpid
    boost::system::result<url_view> mcpUri = parse_uri( ntx.mcpId );
    if (ntx.mcpId.length() == 0 || mcpUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-mcpId-invalid");
    }

    // version check
    if (ntx.version == 0 || ntx.version > CNuCheckTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    // uri check for nuanceId
    boost::system::result<url_view> nuanceUri = parse_uri( ntx.nuanceId );
    if (ntx.nuanceId.length() == 0 || nuanceUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-nuanceId-invalid");
    }

    // hash check - hash of nuance data payload at this time

    // nuanceSatisfied check

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

    // ipAddress check
    if (!ntx.ipAddress.IsIPv4() || !ntx.ipAddress.IsIPv6()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-ip-invalid");
    }

    // uri check for mcpid
    boost::system::result<url_view> mcpUri = parse_uri( ntx.mcpId );
    if (ntx.mcpId.length() == 0 || mcpUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-mcpId-invalid");
    }

    // version check
    if (ntx.version == 0 || ntx.version > CNuXferTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-nuancetx-version");
    }

    // uri check for nuanceId
    boost::system::result<url_view> nuanceUri = parse_uri( ntx.nuanceId );
    if (ntx.nuanceId.length() == 0 || nuanceUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-nuancetx-nuanceId-invalid");
    }

    // toWallet check


    return true;
}

std::string CNuRegTx::ToString() const
{
    return strprintf("CNuRegTx(ipAddress=%s, mcpId=%s, version=%s, name=%s, conceptId=%s, hash=%s)",
        ipAddress, mcpId, version, name, conceptId, hash);
}

std::string CNuUnregTx::ToString() const
{
    return strprintf("CNuUnregTx(ipAddress=%s, mcpId=%s, version=%s, nuanceId=%s, action=%s, postAction=%s)",
        ipAddress, mcpId, version, nuanceId, action, postAction);
}

std::string CNuXferTx::ToString() const
{
    return strprintf("CNuXferTx(ipAddress=%s, mcpId=%s, version=%s, nuanceId=%s, toWallet=%s)",
        ipAddress, mcpId, version, nuanceId, toWallet);
}

std::string CNuCheckTx::ToString() const
{
    return strprintf("CNuCheckTx(ipAddress=%s, mcpId=%s, version=%s, nuanceId=%s, hash=%s, nuanceSatisfied=%s)",
        ipAddress, mcpId, version, nuanceId, hash, nuanceSatisfied);
}

std::string CNuAuthTx::ToString() const
{
    return strprintf("CNuAuthTx(ipAddress=%s, mcpId=%s, version=%s, nuanceId=%s, authorizeWallet=%s)",
        ipAddress, mcpId, version, nuanceId, authorizeWallet);
}

std::string CNuRevAuthTx::ToString() const
{
    return strprintf("CNuRevAuthTx(ipAddress=%s, mcpId=%s, version=%s, nuanceId=%s, revokeWallet=%s)",
        ipAddress, mcpId, version, nuanceId, revokeWallet);
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
    obj.push_back(Pair("hash", hash.ToString()));
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
    obj.push_back(Pair("toWallet", toWallet.ToString()));
}

void CNuCheckTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("nuanceId", nuanceId));
    obj.push_back(Pair("hash", hash.ToString()));
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
    obj.push_back(Pair("authorizeWallet", authorizeWallet.ToString()));
}

void CNuRevAuthTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAddress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("nuanceId", nuanceId));
    obj.push_back(Pair("revokeWallet", revokeWallet.ToString()));
}