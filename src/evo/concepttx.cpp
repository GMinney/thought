// Copyright (c) 2018-2025 Thought Network Ltd
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "deterministicmns.h"
#include "specialtx.h"
#include "concepttx.h"

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

template <typename ConceptTx>
static bool CheckService(const uint256& conceptTxHash, const ConceptTx& conceptTx, CValidationState& state)
{
    if (!conceptTx.ipAddress.IsValid()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ipaddr");
    }
    if (Params().RequireRoutableExternalIP() && !conceptTx.ipAddress.IsRoutable()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ipaddr");
    }

    static int mainnetDefaultPort = CreateChainParams(CBaseChainParams::MAIN)->GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (conceptTx.ipAddress.GetPort() != mainnetDefaultPort) {
            return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ipaddr-port");
        }
    } else if (conceptTx.ipAddress.GetPort() == mainnetDefaultPort) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ipaddr-port");
    }

    if (!conceptTx.ipAddress.IsIPv4() && !conceptTx.ipAddress.IsIPv6()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ipaddr");
    }

    return true;
}

template <typename ConceptTx>
static bool CheckHashSig(const ConceptTx& conceptTx, const CKeyID& keyID, CValidationState& state)
{
    std::string strError;
    if (!CHashSigner::VerifyHash(::SerializeHash(conceptTx), keyID, conceptTx.vchSig, strError)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-sig", false, strError);
    }
    return true;
}

template <typename ConceptTx>
static bool CheckStringSig(const ConceptTx& conceptTx, const CKeyID& keyID, CValidationState& state)
{
    std::string strError;
    if (!CMessageSigner::VerifyMessage(keyID, conceptTx.vchSig, conceptTx.MakeSignString(), strError)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-sig", false, strError);
    }
    return true;
}

template <typename ConceptTx>
static bool CheckHashSig(const ConceptTx& conceptTx, const CBLSPublicKey& pubKey, CValidationState& state)
{
    if (!conceptTx.sig.VerifyInsecure(pubKey, ::SerializeHash(conceptTx))) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-sig", false);
    }
    return true;
}

template <typename ConceptTx>
static bool CheckInputsHash(const CTransaction& tx, const ConceptTx& conceptTx, CValidationState& state)
{
    uint256 inputsHash = CalcTxInputsHash(tx);
    if (inputsHash != conceptTx.inputsHash) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-inputs-hash");
    }

    return true;
}

bool CheckConRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_CONCEPT_REGISTER) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-type");
    }

    CConRegTx ctx;

    // payload check
    if (!GetTxPayload(tx, ctx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-payload");
    }

    // ipAddress check
    if (!ctx.ipAddress.IsIPv4() || !ctx.ipAddress.IsIPv6()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ip-invalid");
    }

    // uri check for mcpid
    boost::system::result<url_view> mcpUri = parse_uri( ctx.mcpId );
    if (ctx.mcpId.length() == 0 || mcpUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-mcpId-invalid");
    }

    // version check
    if (ctx.version == 0 || ctx.version > CConRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-version");
    }

    // name check
    if (ctx.name.size() == 0) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-name");
    }

    // uri check for conceptId
    boost::system::result<url_view> conceptUri = parse_uri( ctx.conceptId );
    if (ctx.conceptId.length() == 0 || conceptUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-conceptId-invalid");
    }

    // conceptHash check - would require the retreval of the concept, then validating it


    // conceptParentId check
    boost::system::result<url_view> conceptParentUri = parse_uri( ctx.conceptParentId );
    if (ctx.conceptParentId.length() == 0 || conceptParentUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-conceptParentId-invalid");
    }

    // conceptVersion check
    std::string version_string(ctx.conceptVersion.begin(), ctx.conceptVersion.end());
    std::regex pattern(R"((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*))");
    if (!std::regex_match(version_string, pattern)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-conceptVersion-invalid");
    }

    // codeLocation check
    boost::system::result<url_view> codeLocationUri = parse_uri( ctx.codeLocation );
    if (ctx.codeLocation.length() == 0 || codeLocationUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-codeLocationUri-invalid");
    }

    return true;
}

bool CheckConUpTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_CONCEPT_UPDATE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-type");
    }

    CConUpTx ctx;
    // payload check
    if (!GetTxPayload(tx, ctx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-payload");
    }

    // uri check for conceptId
    boost::system::result<url_view> conceptUri = parse_uri( ctx.conceptId );
    if (ctx.conceptId.length() == 0 || conceptUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-conceptId-invalid");
    }

    // conceptHash check - would require the retreval of the concept, then validating it


    // conceptVersion check
    std::string version_string(ctx.conceptVersion.begin(), ctx.conceptVersion.end());
    std::regex pattern(R"((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*))");
    if (!std::regex_match(version_string, pattern)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-conceptVersion-invalid");
    }

    // codeLocation check
    boost::system::result<url_view> codeLocationUri = parse_uri( ctx.codeLocation );
    if (ctx.codeLocation.length() == 0 || codeLocationUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-codeLocationUri-invalid");
    }

    return true;
}

bool CheckConUnregTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_CONCEPT_UNREGISTER) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-type");
    }

    CConUnregTx ctx;
    // payload check
    if (!GetTxPayload(tx, ctx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-payload");
    }

    // version string check
    std::string version_string(ctx.version.begin(), ctx.version.end());
    std::regex pattern(R"((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*))");
    if (!std::regex_match(version_string, pattern)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-version-invalid");
    }

    // action check


    // conceptId check
    boost::system::result<url_view> conceptUri = parse_uri( ctx.conceptId );
    if (ctx.conceptId.length() == 0 || conceptUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-conceptId-invalid");
    }

    // need to check is not unregistered already, is valid id, version URI string, and action if valid action

    return true;
}

bool CheckConXferTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_CONCEPT_TRANSFER) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-type");
    }

    CConXferTx ctx;
    if (!GetTxPayload(tx, ctx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-payload");
    }

    // version string check
    std::string version_string(ctx.version.begin(), ctx.version.end());
    std::regex pattern(R"((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*))");
    if (!std::regex_match(version_string, pattern)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-version-invalid");
    }

    // uri check for conceptId
    boost::system::result<url_view> conceptUri = parse_uri( ctx.conceptId );
    if (ctx.conceptId.length() == 0 || conceptUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-conceptId-invalid");
    }

    // toWallet check - would require the retreval of the concept, then validating it

    return true;
}

bool CheckConAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_CONCEPT_AUTHORIZE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-type");
    }

    CConAuthTx ctx;
    if (!GetTxPayload(tx, ctx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-payload");
    }

    // uri check for conceptId
    boost::system::result<url_view> conceptUri = parse_uri( ctx.conceptId );
    if (ctx.conceptId.length() == 0 || conceptUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-conceptId-invalid");
    }

    // authorize wallet check


    // version string check
    std::string version_string(ctx.version.begin(), ctx.version.end());
    std::regex pattern(R"((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*))");
    if (!std::regex_match(version_string, pattern)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-version-invalid");
    }

    return true;
}

bool CheckConRevAuthTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_CONCEPT_REVOKE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-type");
    }

    CConRevAuthTx ctx;
    if (!GetTxPayload(tx, ctx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-payload");
    }

    // uri check for conceptId
    boost::system::result<url_view> conceptUri = parse_uri( ctx.conceptId );
    if (ctx.conceptId.length() == 0 || conceptUri.has_error()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-conceptId-invalid");
    }

    // reevoke wallet check


    // version string check
    std::string version_string(ctx.version.begin(), ctx.version.end());
    std::regex pattern(R"((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*))");
    if (!std::regex_match(version_string, pattern)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-version-invalid");
    }

    return true;
}

std::string CConRegTx::ToString() const
{
    return strprintf("CConRegTx(ipAddress=%s, mcpId=%s, version=%s, name=%s, conceptId=%s, conceptHash=%s, conceptParentId=%s, conceptVersion=%s, codeLocation=%s)",
        ipAddress, mcpId, version, name, conceptId, conceptHash, conceptParentId, conceptVersion, codeLocation);
}

std::string CConAuthTx::ToString() const
{
    return strprintf("CConAuthTx(conceptId=%s, authorizeWallet=%s, version=%s)",
        conceptId, authorizeWallet.ToString(), version);
}

std::string CConUpTx::ToString() const
{
    return strprintf("CConUpTx(conceptId=%s, conceptHash=%s, conceptVersion=%s, codeLocation=%s)",
        conceptId, conceptHash.ToString(), conceptVersion, codeLocation);
}

std::string CConRevAuthTx::ToString() const
{
    return strprintf("CConRevAuthTx(conceptId=%s, revokeWallet=%s, version=%s)",
        conceptId, revokeWallet.ToString(), version);
}

std::string CConUnregTx::ToString() const
{
    return strprintf("CConUnregTx(conceptId=%s, version=%s, action=%s)",
        conceptId, version, action);
}

std::string CConXferTx::ToString() const
{
    return strprintf("CConXferTx(conceptId=%s, toWallet=%s, version=%s)",
        conceptId, toWallet.ToString(), version);
}

void CConRegTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("ipAdress", ipAddress.ToString()));
    obj.push_back(Pair("mcpId", mcpId));
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("name", name));
    obj.push_back(Pair("conceptId", conceptId));
    obj.push_back(Pair("conceptHash", conceptHash.ToString()));
    obj.push_back(Pair("conceptParentId", conceptParentId));
    obj.push_back(Pair("conceptVersion", conceptVersion));
    obj.push_back(Pair("codeLocation", codeLocation));
}

void CConAuthTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("conceptId", conceptId));
    obj.push_back(Pair("authorizeWallet", authorizeWallet.ToString()));
    obj.push_back(Pair("version", version));
}

void CConUpTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("conceptId", conceptId));
    obj.push_back(Pair("conceptHash", conceptHash.ToString()));
    obj.push_back(Pair("conceptVersion", conceptVersion));
    obj.push_back(Pair("codeLocation", codeLocation));
}

void CConRevAuthTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("conceptId", conceptId));
    obj.push_back(Pair("revokeWallet", revokeWallet.ToString()));
    obj.push_back(Pair("version", version));
}

void CConUnregTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("conceptId", conceptId));
    obj.push_back(Pair("action", action));
}

void CConXferTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("version", version));
    obj.push_back(Pair("conceptId", conceptId));
    obj.push_back(Pair("toWallet", toWallet.ToString()));
}