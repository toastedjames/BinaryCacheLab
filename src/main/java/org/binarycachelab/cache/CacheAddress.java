package org.binarycachelab.cache;

import java.util.Objects;

public final class CacheAddress {

    private final long address;
    private final long cacheLine;
    private final long cacheSet;
    private final long tag;

    public CacheAddress(long address, CacheConfig config) {
        Objects.requireNonNull(
                config,
                "Cache configuration must not be null."
        );

        this.address = address;
        this.cacheLine = config.getCacheLine(address);
        this.cacheSet = config.getCacheSet(address);
        this.tag = config.getTag(address);
    }

    public long getAddress() {
        return address;
    }

    public long getCacheLine() {
        return cacheLine;
    }

    public long getCacheSet() {
        return cacheSet;
    }

    public long getTag() {
        return tag;
    }

    @Override
    public String toString() {
        return String.format(
                "Address=0x%X | CacheLine=%s | Set=%s | Tag=%s",
                address,
                Long.toUnsignedString(cacheLine),
                Long.toUnsignedString(cacheSet),
                Long.toUnsignedString(tag)
        );
    }
}