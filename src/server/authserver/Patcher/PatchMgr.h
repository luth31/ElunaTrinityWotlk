#ifndef _PATCHMGR_H
#define _PATCHMGR_H

#include "Common.h"
#include "AuthSession.h"
#include "openssl/md5.h"
#include <fstream>

class AuthSession;

enum PatchingStatus {
    PATCHING_ENABLED,
    PATCHING_DISABLED
};

class PatchMgr {
    private:
        PatchMgr();
        ~PatchMgr();

        void GetPatchMD5(std::ifstream& file, uint64 size, uint8 MD5[MD5_DIGEST_LENGTH]);
        PatchingStatus Status;
    public:
        PatchMgr(PatchMgr const&) = delete;
        PatchMgr(PatchMgr&&) = delete;
        PatchMgr& operator= (PatchMgr const&) = delete;
        PatchMgr& operator= (PatchMgr&&) = delete;

        static PatchMgr* instance();

        struct PatchInfo {
            uint16 Build;
            std::string Path;
            uint64 Size;
            char Locale[4];
            uint8 MD5[MD5_DIGEST_LENGTH];
        };

        void Initialize();
        void LoadPatches();
        bool IsEnabled() { return Status == PatchingStatus::PATCHING_ENABLED; }
        void Disable() { Status = PatchingStatus::PATCHING_DISABLED; }
        void Enable() { Status = PatchingStatus::PATCHING_ENABLED; }

        bool CanPatch(uint16 Build);
        bool Patch(uint16 Build, AuthSession* Session);
        std::unordered_map<uint16, PatchInfo*> Patches;
};

#define sPatcher PatchMgr::instance()
#endif
