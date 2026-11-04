#include "pin.H"
#include <cstdio>
#include <string>

#if !defined(TARGET_IA32E) || !defined(TARGET_LINUX)
#error This prototype requires Linux Intel64.
#endif

KNOB<std::string> TracePath(KNOB_MODE_WRITEONCE, "pintool", "o", "trace.csv", "Raw memory trace");
KNOB<std::string> ImagesPath(KNOB_MODE_WRITEONCE, "pintool", "images", "images.csv", "Image lifecycle log");
KNOB<std::string> MetaPath(KNOB_MODE_WRITEONCE, "pintool", "meta", "trace.properties", "Collection metadata");
KNOB<std::string> MapsPath(KNOB_MODE_WRITEONCE, "pintool", "maps", "maps.log", "Point-in-time /proc/self/maps snapshots");
KNOB<UINT64> MaxEvents(KNOB_MODE_WRITEONCE, "pintool", "max_events", "2000000", "Maximum memory events");
KNOB<UINT64> MaxSnapshots(KNOB_MODE_WRITEONCE, "pintool", "max_snapshots", "4096", "Maximum mapping snapshots");

KNOB<BOOL> AllowEmpty(KNOB_MODE_WRITEONCE, "pintool", "allow_empty", "0", "Accept a complete zero-data-access program trace");

static FILE* traceFile = nullptr;
static FILE* imageFile = nullptr;
static FILE* mapsFile = nullptr;
static PIN_LOCK lock;
static UINT64 events = 0, imageEvents = 0;
static UINT64 snapshots = 0;
static UINT32 threads = 0, mainImages = 0;
static bool failed = false;

static bool Metadata(const char* status, const char* reason, INT32 code, ADDRINT ip)
{
    FILE* f = std::fopen(MetaPath.Value().c_str(), "w");
    if (!f) return false;
    const int written = std::fprintf(f,
        "status=%s\nreason=%s\ntracer_version=whole-2\nbackend=PIN\n"
        "scope=pin-instrumented-user-space\naddress_space=raw-virtual\n"
        "event_semantics=before-instruction-pin-predication\n"
        "read_modify_write=separate-read-then-write\n"
        "observation_filter=none\nnormalization=none\n"
        "kernel_memory_accesses=excluded\ninstruction_fetches=excluded\n"
        "image_high_address=inclusive-envelope-not-contiguous-mapping\n"
        "image_name_encoding=hex-bytes\n"
        "mapping_source=/proc/self/maps\n"
        "mapping_scope=mixed-instrumented-process-address-space\n"
        "mapping_semantics=point-in-time-not-allocation-identity\n"
        "mapping_triggers=first-memory,image-callback,syscall-return\n"
        "mapping_snapshot_order=next-memory-sequence-then-snapshot-id\n"
        "mapping_continuity=not-guaranteed\n"
        "empty_trace_allowed=%s\n"
        "mapping_snapshots=%llu\n"
        "events=%llu\nimage_events=%llu\napplication_threads=%u\n"
        "main_images=%u\napplication_exit=%d\nmax_events=%llu\n"
        "failure_ip=0x%llx\npreservation_verdict=NOT_EVALUATED\n",
        status, reason, AllowEmpty.Value() ? "true" : "false", static_cast<unsigned long long>(snapshots), static_cast<unsigned long long>(events),
        static_cast<unsigned long long>(imageEvents), threads, mainImages, code,
        static_cast<unsigned long long>(MaxEvents.Value()), static_cast<unsigned long long>(ip));
    const bool closed = std::fclose(f) == 0;
    return written >= 0 && closed;
}

static VOID Fail(const char* reason, ADDRINT ip)
{
    failed = true;
    Metadata("incomplete", reason, -1, ip);
    std::fprintf(stderr, "WholeProgramMemoryTracer: %s at 0x%llx\n",
                 reason, static_cast<unsigned long long>(ip));
    if (traceFile) std::fflush(traceFile);
    if (imageFile) std::fflush(imageFile);
    if (mapsFile) std::fflush(mapsFile);
    PIN_ExitProcess(2);
}

static VOID Snapshot(const char* reason, THREADID tid)
{
    PIN_GetLock(&lock, tid + 1);
    const char* error = nullptr;
    if (snapshots >= MaxSnapshots.Value()) {
        error = "mapping-snapshot-limit-reached";
    } else {
        FILE* input = std::fopen("/proc/self/maps", "r");
        if (!input) error = "mapping-source-open-failed";
        else {
            const UINT64 id = snapshots;
            bool okay = std::fprintf(mapsFile,
                "# snapshot=%llu next_memory_sequence=%llu reason=%s\n",
                static_cast<unsigned long long>(id),
                static_cast<unsigned long long>(events), reason) >= 0;
            UINT64 bytes = 0;
            int character;
            while ((character = std::fgetc(input)) != EOF) {
                if (++bytes > 4 * 1024 * 1024) {
                    error = "mapping-snapshot-too-large";
                    break;
                }
                if (std::fputc(character, mapsFile) == EOF) {
                    error = "mapping-log-write-failed";
                    break;
                }
            }
            if (std::ferror(input)) error = "mapping-source-read-failed";
            if (std::fclose(input) != 0) error = "mapping-source-close-failed";
            if (!error && bytes == 0) error = "mapping-source-empty";
            if (!error && okay) {
                okay = std::fprintf(mapsFile, "# end_snapshot=%llu\n",
                    static_cast<unsigned long long>(id)) >= 0;
                if (okay) ++snapshots;
            }
            if (!okay && !error) error = "mapping-log-write-failed";
        }
    }
    PIN_ReleaseLock(&lock);
    if (error) Fail(error, 0);
}

static VOID ThreadStart(THREADID tid, CONTEXT*, INT32, VOID*)
{
    PIN_GetLock(&lock, tid + 1);
    ++threads;
    bool unsupported = threads != 1;
    PIN_ReleaseLock(&lock);
    if (unsupported) Fail("additional-thread", 0);
}

static std::string HexName(const std::string& name)
{
    const char* digits = "0123456789abcdef";
    std::string result;
    for (unsigned char c : name) {
        result += digits[c >> 4]; result += digits[c & 15];
    }
    return result;
}

static VOID ImageEvent(IMG image, const char* action)
{
    const std::string name = HexName(IMG_Name(image));
    const UINT32 id = IMG_Id(image);
    const bool main = IMG_IsMainExecutable(image);
    const ADDRINT low = IMG_LowAddress(image), high = IMG_HighAddress(image);
    const ADDRINT bias = IMG_LoadOffset(image);
    PIN_GetLock(&lock, 1);
    if (main && action[0] == 'L') ++mainImages;
    const int result = std::fprintf(imageFile, "%llu,%s,%llu,%u,%u,0x%llx,0x%llx,0x%llx,%s\n",
        static_cast<unsigned long long>(imageEvents++), action,
        static_cast<unsigned long long>(events), id, main ? 1u : 0u,
        static_cast<unsigned long long>(low), static_cast<unsigned long long>(high),
        static_cast<unsigned long long>(bias), name.c_str());
    PIN_ReleaseLock(&lock);
    if (result < 0) Fail("image-log-write-failed", 0);
}

static VOID LoadImage(IMG image, VOID*) {
    ImageEvent(image, "LOAD"); Snapshot("image-load-callback", 0);
}
static VOID UnloadImage(IMG image, VOID*) {
    ImageEvent(image, "UNLOAD"); Snapshot("image-unload-callback", 0);
}

static VOID Record(THREADID tid, ADDRINT ip, ADDRINT address, UINT32 size, UINT32 write)
{
    if (events == 0) Snapshot("first-memory", tid);
    PIN_GetLock(&lock, tid + 1);
    const char* error = nullptr;
    if (events >= MaxEvents.Value()) error = "event-limit-reached";
    else if (!size || address + (size - 1) < address) error = "invalid-memory-span";
    else {
        int result = std::fprintf(traceFile, "%llu,%u,0x%llx,0x%llx,%u,%s,PIN\n",
            static_cast<unsigned long long>(events), static_cast<unsigned int>(tid),
            static_cast<unsigned long long>(ip), static_cast<unsigned long long>(address),
            size, write ? "WRITE" : "READ");
        if (result < 0) error = "trace-write-failed";
        else ++events;
    }
    PIN_ReleaseLock(&lock);
    if (error) Fail(error, ip);
}

static VOID SyscallExit(THREADID tid, CONTEXT*, SYSCALL_STANDARD, VOID*)
{
    Snapshot("syscall-return", tid);
}

static VOID Unsupported(ADDRINT ip) { Fail("unsupported-memory-instruction", ip); }

static VOID Instrument(INS ins, VOID*)
{
    const UINT32 count = INS_MemoryOperandCount(ins);
    // Test before calling MemoryOperandSize: scattered operands need another API.
    if ((count > 0 || INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins))
            && !INS_IsStandardMemop(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(Unsupported),
                       IARG_INST_PTR, IARG_END);
        return;
    }
    for (UINT32 operand = 0; operand < count; ++operand) {
        const UINT32 size = INS_MemoryOperandSize(ins, operand);
        if (INS_MemoryOperandIsRead(ins, operand)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(Record),
                IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYOP_EA, operand,
                IARG_UINT32, size, IARG_UINT32, 0, IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, operand)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(Record),
                IARG_THREAD_ID, IARG_INST_PTR, IARG_MEMORYOP_EA, operand,
                IARG_UINT32, size, IARG_UINT32, 1, IARG_END);
        }
    }
}

static VOID SyscallEntry(THREADID, CONTEXT* ctxt, SYSCALL_STANDARD standard, VOID*)
{
    // Linux x86-64 fork/clone/exec change the supported process/thread model.
    if (standard != SYSCALL_STANDARD_IA32E_LINUX) {
        Fail("unsupported-syscall-abi", PIN_GetContextReg(ctxt, REG_INST_PTR));
        return;
    }
    const ADDRINT number = PIN_GetSyscallNumber(ctxt, standard);
    if (number == 56 || number == 57 || number == 58 || number == 59
            || number == 322 || number == 435) {
        Fail("fork-clone-exec-unsupported", PIN_GetContextReg(ctxt, REG_INST_PTR));
    }
}

static VOID Finish(INT32 code, VOID*)
{
    bool ioOkay = true;
    if (traceFile) { ioOkay = std::fclose(traceFile) == 0; traceFile = nullptr; }
    if (imageFile) { ioOkay = (std::fclose(imageFile) == 0) && ioOkay; imageFile = nullptr; }
    if (mapsFile) { ioOkay = (std::fclose(mapsFile) == 0) && ioOkay; mapsFile = nullptr; }
    if (failed) return; // Keep the original failure metadata.
    const bool complete = ioOkay && code == 0 && threads == 1 && mainImages == 1 && (events > 0 || AllowEmpty.Value()) && snapshots > 0;
    if (!Metadata(complete ? "complete" : "incomplete",
                  complete ? "normal-exit" : "exit-count-or-io-check-failed", code, 0)) {
        std::fprintf(stderr, "WholeProgramMemoryTracer: metadata-write-failed\n");
    }
}

int main(int argc, char** argv)
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 2;
    PIN_InitLock(&lock);
    // Use a fresh output directory. Existing files must never be overwritten.
    FILE* initial = std::fopen(MetaPath.Value().c_str(), "wx");
    if (!initial) { std::fprintf(stderr, "Cannot create fresh metadata file\n"); return 2; }
    std::fprintf(initial, "status=incomplete\nreason=initializing\ntracer_version=whole-2\n");
    if (std::fclose(initial) != 0) return 2;
    traceFile = std::fopen(TracePath.Value().c_str(), "wx");
    imageFile = std::fopen(ImagesPath.Value().c_str(), "wx");
    mapsFile = std::fopen(MapsPath.Value().c_str(), "wx");
    if (!traceFile || !imageFile || !mapsFile || !MaxEvents.Value() || !MaxSnapshots.Value()) {
        std::fprintf(stderr, "Cannot create fresh trace/image files, or invalid event limit\n");
        return 2;
    }
    std::fprintf(traceFile, "sequence,thread_id,instruction_address,memory_address,access_size_bytes,access_type,source_backend\n");
    std::fprintf(imageFile, "image_sequence,action,next_memory_sequence,image_id,is_main,low,high_inclusive,load_offset,name_hex\n");
    INS_AddInstrumentFunction(Instrument, nullptr);
    IMG_AddInstrumentFunction(LoadImage, nullptr);
    IMG_AddUnloadFunction(UnloadImage, nullptr);
    PIN_AddThreadStartFunction(ThreadStart, nullptr);
    PIN_AddSyscallEntryFunction(SyscallEntry, nullptr);
    PIN_AddSyscallExitFunction(SyscallExit, nullptr);
    PIN_AddFiniFunction(Finish, nullptr);
    PIN_StartProgram();
    return 0;
}
