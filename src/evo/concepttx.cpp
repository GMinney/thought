// Copyright (c) 2018-2025 Thought Network Ltd
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/deterministicmns.h>
#include <evo/concepttx.h>
#include <evo/specialtx.h>

#include <chainparams.h>
#include <clientversion.h>
#include <coins.h>
#include <hash.h>
#include <messagesigner.h>
#include <script/standard.h>
#include <validation.h>

template <typename ConceptTx>
static bool CheckService(const uint256& conceptTxHash, const ConceptTx& conceptTx, CValidationState& state)
{
    if (!conceptTx.addr.IsValid()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ipaddr");
    }
    if (Params().RequireRoutableExternalIP() && !conceptTx.addr.IsRoutable()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ipaddr");
    }

    static int mainnetDefaultPort = CreateChainParams(CBaseChainParams::MAIN)->GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (conceptTx.addr.GetPort() != mainnetDefaultPort) {
            return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ipaddr-port");
        }
    } else if (conceptTx.addr.GetPort() == mainnetDefaultPort) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ipaddr-port");
    }

    if (!conceptTx.addr.IsIPv4() && !conceptTx.addr.IsIPv6()) {
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
    if (!GetTxPayload(tx, ctx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-payload");
    }

    if (ctx.version == 0 || ctx.version > CConRegTx::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-version");
    }

    if (ctx.mcpId.is_nil() || ctx.mcpId.version() != 4) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-mcpId");
    }

    if (!ctx.ipAddress.IsIPv4()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-concepttx-ip-not-v4");
    }

    // Profanity check in name?

    // check conceptID
    // check conceptHash
    // check ParentId
    // check conceptVersion
    // check codeLocation

    return true;
}

bool CheckConUpTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_CONCEPT_UPDATE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-type");
    }

    CConUpTx ctx;
    if (!GetTxPayload(tx, ctx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-payload");
    }

    // need to check not null, exists, has authorization, is not unregistered
    if (!ctx.conceptId.IsNull()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-conceptId");
    }

    // uint256 conceptId; // txid - hash
    // uint256 conceptHash; // hash of concept
    // std::vector<unsigned char> conceptVersion; // String
    // std::vector<unsigned char> codeLocation; // URI

    return true;
}

bool CheckConUnregTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nType != TRANSACTION_CONCEPT_UNREGISTER) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-type");
    }

    CConUnregTx ctx;
    if (!GetTxPayload(tx, ctx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-concepttx-payload");
    }

    // need to check is not unregistered already, is valid id, version URI string, and action if valid action

    // // Concept un-register Fields
    // uint256 conceptId; // txid - hash
    // std::vector<unsigned char> version; // String
    // std::vector<unsigned char> action; // enum

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

    // need to check

    // // Concept transfer Fields
    // uint256 conceptId; // URI
    // uint256 toWallet; // hash of concept
    // std::vector<unsigned char> version; // String
    

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

    // need to check

    // uint256 conceptId; // txid - hash
    // uint256 authorizeWallet; // hash of concept
    // std::vector<unsigned char> version; // String

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

    // need to check

    // uint256 conceptId; // txid - hash
    // uint256 revokeWallet; // hash of concept
    // std::vector<unsigned char> version; // String

    return true;
}

std::string CConRegTx::ToString() const
{
    return strprintf("CConRegTx(ipAddress=%d, mcpId=%s, version=%d, name=%s, conceptId=%s, conceptHash=%s, conceptParentId=%d, conceptVersion=%s, codeLocation=%d)",
        ipAddress, mcpId.ToString(), version, name, conceptId, conceptHash, conceptParentId, conceptVersion, codeLocation);
}

std::string CConAuthTx::ToString() const
{
    return strprintf("CConAuthTx(conceptId=%s, authorizeWallet=%d, version=%s)",
        conceptId, authorizeWallet.ToString(), version);
}

std::string CConUpTx::ToString() const
{
    return strprintf("CConUpTx(conceptId=%s, conceptHash=%s, conceptVersion=%d, codeLocation=%s)",
        conceptId, conceptHash.ToString(), conceptVersion, codeLocation);
}

std::string CConRevAuthTx::ToString() const
{
    return strprintf("CConRevAuthTx(conceptId=%s, revokeWallet=%s, version=%d)",
        conceptId, revokeWallet.ToString(), version);
}

std::string CConUnregTx::ToString() const
{
    return strprintf("CConUnregTx(conceptId=%s, version=%s, action=%d)",
        conceptId, version.ToString(), action);
}

std::string CConXferTx::ToString() const
{
    return strprintf("CConXferTx(conceptId=%s, toWallet=%s, version=%d)",
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
    obj.push_back(Pair("conceptHash", conceptHash));
    obj.push_back(Pair("conceptParentId", conceptParentId));
    obj.push_back(Pair("conceptVersion", conceptVersion));
    obj.push_back(Pair("codeLocation", codeLocation));
}

void CConAuthTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("conceptId", conceptId));
    obj.push_back(Pair("authorizeWallet", authorizeWallet));
    obj.push_back(Pair("version", version));
}

void CConUpTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("conceptId", conceptId));
    obj.push_back(Pair("conceptHash", conceptHash));
    obj.push_back(Pair("conceptVersion", conceptVersion));
    obj.push_back(Pair("codeLocation", codeLocation));
}

void CConRevAuthTx::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("conceptId", conceptId));
    obj.push_back(Pair("revokeWallet", revokeWallet));
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
    obj.push_back(Pair("toWallet", toWallet));
}