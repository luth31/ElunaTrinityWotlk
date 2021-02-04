#include "PatchMgr.h"
#include "Config.h"
#include "ByteBuffer.h"
#include "AuthCodes.h"
#include "AuthSession.h"
#include "openssl/md5.h"
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <fstream>
#include "Patcher.h"

#include <iomanip>
namespace algo = boost::algorithm;
namespace fs = boost::filesystem;

PatchMgr::PatchMgr() {
    Disable();
}

PatchMgr::~PatchMgr() {
}

void PatchMgr::GetPatchMD5(std::ifstream& file, uint64 size, uint8 MD5[MD5_DIGEST_LENGTH]) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    uint8 buffer[1024 * 512];
    while (!file.eof()) {
        file.read((char*)buffer, sizeof(buffer));
        MD5_Update(&ctx, buffer, file.gcount());
    }
    uint64 remaining = size - file.tellg();
    if (remaining != 0) {
        file.read((char*)buffer, remaining);
        MD5_Update(&ctx, buffer, file.gcount());
    }
    MD5_Final(MD5, &ctx);
}

PatchMgr* PatchMgr::instance() {
    static PatchMgr instance;
    return &instance;
}

void PatchMgr::Initialize() {
    LoadPatches();
}

void PatchMgr::LoadPatches() {
    Patches.clear();
    fs::path PatchDir(sConfigMgr->GetStringDefault("PatchDir", "./"));
    if (!fs::exists(PatchDir) || !fs::is_directory(PatchDir)) {
        Disable();
        return;
    }
    int count = 0;
    for (auto& file : boost::filesystem::directory_iterator(PatchDir)) {
        std::string filename = file.path().stem().string();
        std::string extension = file.path().extension().string();
        if (algo::to_lower_copy(extension) != ".mpq" || !std::all_of(filename.begin(), filename.end(), ::isdigit))
            continue;
        PatchInfo* info = new PatchInfo;
        info->Build = boost::lexical_cast<uint16>(filename);
        info->Path = file.path().string();
        std::ifstream patch(info->Path, std::ios::binary);
        if (!patch.is_open())
            continue;
        info->Size = fs::file_size(file);
        GetPatchMD5(patch, info->Size, info->MD5);
        patch.close();
        ++count;
        Patches.insert({ info->Build, info });
    }
    if (count > 0) {
        TC_LOG_INFO("patcher", "[PatchMgr] Loaded %d patches.", count);
        Enable();
    }
    else {
        Disable();
    }
}

bool PatchMgr::CanPatch(uint16 Build, std::string Locale) {
    if (!IsEnabled())
        return false;
    if (Patches.find(Build) != Patches.end()) {
        return true;
    }
    return false;
}

bool PatchMgr::Patch(uint16 Build, AuthSession* Session) {
    PatchInfo* Patch = Patches.find(Build)->second;
    ByteBuffer pkt;
    pkt << uint8(0x01); // AUTH_LOGON_PROOF
    pkt << uint8(LOGIN_DOWNLOAD_FILE);
    Session->SendPacket(pkt);

    sXferInit_C Xfer;
    Xfer.cmd = 0x30; // XFER_INITIATE
    Xfer.nameLength = 5;
    Xfer.fileName[0] = 'P';
    Xfer.fileName[1] = 'a';
    Xfer.fileName[2] = 't';
    Xfer.fileName[3] = 'c';
    Xfer.fileName[4] = 'h';
    Xfer.fileSize = Patch->Size;
    memcpy(Xfer.MD5, Patch->MD5, sizeof(Patch->MD5));
    pkt.resize(sizeof(Xfer));
    memcpy(pkt.contents(), &Xfer, sizeof(Xfer));
    Session->SendPacket(pkt);
    Patcher* patcher = new Patcher(Session, Patch);
    Session->_patcher = patcher;
    return true;
}
