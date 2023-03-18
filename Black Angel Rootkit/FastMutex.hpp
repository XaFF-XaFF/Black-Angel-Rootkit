#pragma once
#include <ntddk.h>

class FastMutex {
public:
	void Init();

	void Lock();
	void Unlock();

private:
	FAST_MUTEX _mutex;
};