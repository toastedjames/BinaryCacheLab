package org.binarycachelab.cache;

public final class CacheConfig {

    private final int cacheSizeBytes;
    private final int cacheLineSizeBytes;
    private final int associativity;
    private final long numberOfSets;

    public CacheConfig(
            int cacheSizeBytes,
            int cacheLineSizeBytes,
            int associativity
    ) {
        if (cacheSizeBytes <= 0) {
            throw new IllegalArgumentException(
                    "Cache size must be positive."
            );
        }

        if (cacheLineSizeBytes <= 0) {
            throw new IllegalArgumentException(
                    "Cache line size must be positive."
            );
        }

        if (associativity <= 0) {
            throw new IllegalArgumentException(
                    "Associativity must be positive."
            );
        }

        // Promote before multiplication to avoid integer overflow.
        long bytesPerSet = (long) cacheLineSizeBytes * associativity;

        if (cacheSizeBytes % bytesPerSet != 0) {
            throw new IllegalArgumentException(
                    "Cache size must be divisible by "
                            + "line size multiplied by associativity."
            );
        }

        long sets = cacheSizeBytes / bytesPerSet;

        if (sets <= 0) {
            throw new IllegalArgumentException(
                    "Number of cache sets must be positive."
            );
        }

        this.cacheSizeBytes = cacheSizeBytes;
        this.cacheLineSizeBytes = cacheLineSizeBytes;
        this.associativity = associativity;
        this.numberOfSets = sets;
    }

    public int getCacheSizeBytes() {
        return cacheSizeBytes;
    }

    public int getCacheLineSizeBytes() {
        return cacheLineSizeBytes;
    }

    public int getAssociativity() {
        return associativity;
    }

    public long getNumberOfSets() {
        return numberOfSets;
    }

    public long getCacheLine(long address) {
        return Long.divideUnsigned(address, cacheLineSizeBytes);
    }

    public long getCacheSet(long address) {
        return Long.remainderUnsigned(
                getCacheLine(address),
                numberOfSets
        );
    }

    public long getTag(long address) {
        return Long.divideUnsigned(
                getCacheLine(address),
                numberOfSets
        );
    }

    @Override
    public String toString() {
        return "CacheConfig{"
                + "cacheSizeBytes=" + cacheSizeBytes
                + ", cacheLineSizeBytes=" + cacheLineSizeBytes
                + ", associativity=" + associativity
                + ", numberOfSets=" + numberOfSets
                + '}';
    }
}