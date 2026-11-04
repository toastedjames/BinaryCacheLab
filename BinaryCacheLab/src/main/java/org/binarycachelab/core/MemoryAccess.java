package org.binarycachelab.core;

import java.util.Objects;

public final class MemoryAccess {

    public enum AccessType {
        READ,
        WRITE,
        READ_WRITE
    }

    public enum SourceBackend {
        PIN,
        GEM5,
        SYNTHETIC
    }

    private final long sequence;
    private final long threadId;
    private final long instructionAddress;
    private final long memoryAddress;
    private final int accessSizeBytes;
    private final AccessType accessType;
    private final SourceBackend sourceBackend;

    public MemoryAccess(
            long sequence,
            long threadId,
            long instructionAddress,
            long memoryAddress,
            int accessSizeBytes,
            AccessType accessType,
            SourceBackend sourceBackend
    ) {
        if (sequence < 0) {
            throw new IllegalArgumentException(
                    "Sequence must be non-negative."
            );
        }

        if (threadId < 0) {
            throw new IllegalArgumentException(
                    "Thread ID must be non-negative."
            );
        }

        if (accessSizeBytes <= 0) {
            throw new IllegalArgumentException(
                    "Access size must be positive."
            );
        }

        long lastByteAddress = memoryAddress + (accessSizeBytes - 1L);

        if (Long.compareUnsigned(lastByteAddress, memoryAddress) < 0) {
            throw new IllegalArgumentException(
                    "Memory access wraps around the 64-bit address space."
            );
        }

        this.sequence = sequence;
        this.threadId = threadId;
        this.instructionAddress = instructionAddress;
        this.memoryAddress = memoryAddress;
        this.accessSizeBytes = accessSizeBytes;
        this.accessType = Objects.requireNonNull(
                accessType,
                "Access type must not be null."
        );
        this.sourceBackend = Objects.requireNonNull(
                sourceBackend,
                "Source backend must not be null."
        );
    }

    public long getSequence() {
        return sequence;
    }

    public long getThreadId() {
        return threadId;
    }

    public long getInstructionAddress() {
        return instructionAddress;
    }

    public long getMemoryAddress() {
        return memoryAddress;
    }

    public int getAccessSizeBytes() {
        return accessSizeBytes;
    }

    public AccessType getAccessType() {
        return accessType;
    }

    public SourceBackend getSourceBackend() {
        return sourceBackend;
    }

    public boolean isRead() {
        return accessType == AccessType.READ
                || accessType == AccessType.READ_WRITE;
    }

    public boolean isWrite() {
        return accessType == AccessType.WRITE
                || accessType == AccessType.READ_WRITE;
    }

    @Override
    public String toString() {
        return String.format(
                "MemoryAccess{sequence=%d, threadId=%d, "
                        + "instructionAddress=0x%X, memoryAddress=0x%X, "
                        + "size=%d, type=%s, backend=%s}",
                sequence,
                threadId,
                instructionAddress,
                memoryAddress,
                accessSizeBytes,
                accessType,
                sourceBackend
        );
    }
}