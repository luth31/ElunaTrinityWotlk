#ifndef _PATCHER_H_
#define _PATCHER_H_

#include "AuthSession.h"
#include "PatchMgr.h"
#include "Common.h"

class AuthSession;

class Patcher {
    public:
        Patcher(Patcher const&) = delete;
        Patcher(Patcher&&) = delete;
        Patcher& operator= (Patcher const&) = delete;
        Patcher& operator= (Patcher&&) = delete;

        Patcher(AuthSession* Session, PatchMgr::PatchInfo* Patch);
        ~Patcher();

        void Init(uint64 start_pos = 0);
        void Stop();
    private:
        AuthSession* _session;
        PatchMgr::PatchInfo* _patch;
        bool _stopped;
};
#endif
