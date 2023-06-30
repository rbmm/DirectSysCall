#pragma once

BOOL InitSysCall();
void DestroySysCall();

// #define _PREPARE_

#ifdef _PREPARE_
void Prepare(_In_ const PCSTR names[]);
#endif