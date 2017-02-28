#ifdef __cplusplus
#define CCCOREDUMP_API extern "C" __declspec(dllexport)
#else
#define CCCOREDUMP_API __declspec(dllexport)
#endif

CCCOREDUMP_API 	void InitMinDump(char *dumpFileName);