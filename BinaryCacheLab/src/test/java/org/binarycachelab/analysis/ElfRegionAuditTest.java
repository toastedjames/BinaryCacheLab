package org.binarycachelab.analysis;

import java.nio.*;
import java.util.Arrays;

/** Synthetic ELF metadata controls; these do not execute or prove a binary. */
public final class ElfRegionAuditTest {
    private static int tests;
    public static void main(String[] args) {
        var r=ElfRegionAudit.audit(fixture(8,0x400390,0x400384),0x400380,8);
        check(r.relocations().get(0).interiorTarget(),"Interior relative pointer missed");
        check(!r.relocations().get(0).writeOverlap(),"Disjoint write classified as overlap");
        r=ElfRegionAudit.audit(fixture(8,0x40037c,0),0x400380,8);
        check(r.relocations().get(0).writeOverlap(),"Cross-boundary write missed");
        r=ElfRegionAudit.audit(fixture(8,0x400388,0x400388),0x400380,8);
        check(!r.relocations().get(0).writeOverlap()&&!r.relocations().get(0).interiorTarget(),"Half-open end mishandled");
        r=ElfRegionAudit.audit(fixture(6,0x400380,0),0x400380,8);
        check(r.blockers().contains("UNRESOLVED_SYMBOL_OR_RELOCATION_TARGET"),"Symbol binding treated as resolved");
        r=ElfRegionAudit.audit(fixture(5,0x400370,0),0x400380,8);
        check(r.blockers().contains("UNKNOWN_RELOCATION_WRITE_EXTENT"),"COPY unknown width lost");
        byte[] raw=fixture(8,0x400390,0); ByteBuffer b=buffer(raw);
        b.putLong(0x230,23).putLong(0x238,0x400300);
        b.putLong(0x240,2).putLong(0x248,24);
        b.putLong(0x250,20).putLong(0x258,7);
        r=ElfRegionAudit.audit(raw,0x400380,8);
        check(r.relocations().size()==1,"Overlapping relocation views double counted");
        raw=fixture(8,0x400390,0); b=buffer(raw);
        b.putLong(0x230,36).putLong(0x238,0x400340);
        r=ElfRegionAudit.audit(raw,0x400380,8);
        check(r.blockers().contains("DT_RELR_UNSUPPORTED"),"RELR silently omitted");
        raw=fixture(8,0x400390,0); b=buffer(raw); b.putLong(0x230,17).putLong(0x238,0x400340);
        check(ElfRegionAudit.audit(raw,0x400380,8).blockers().contains("DT_REL_UNSUPPORTED"),"REL silently omitted");
        raw=fixture(8,0x400390,0); buffer(raw).putShort(16,(short)3);
        check(ElfRegionAudit.audit(raw,0x400380,8).elfType()==3,"ET_DYN rejected");
        r=ElfRegionAudit.audit(fixture(0,0,0),0x400380,8);
        check(r.json().contains("\"automatic_rewrite_allowed\": false") &&
              r.blockers().contains("COMPLETE_REFERENCE_COVERAGE_NOT_ESTABLISHED"),"Empty inventory authorized rewriting");
        reject(new byte[10],0x400380,8);
        raw=fixture(8,0x400390,0); raw[5]=2; reject(raw,0x400380,8);
        raw=fixture(8,0x400390,0); buffer(raw).putShort(18,(short)3); reject(raw,0x400380,8);
        reject(fixture(8,0x400390,0),0x400380,0);
        reject(fixture(8,0x400390,0),Long.MAX_VALUE,2);
        reject(fixture(8,0x400390,0),0x4003fc,8);
        raw=fixture(8,0x400390,0); buffer(raw).putLong(0x218,25); reject(raw,0x400380,8);
        raw=fixture(8,0x400390,0); buffer(raw).putLong(0x228,16); reject(raw,0x400380,8);
        raw=fixture(8,0x400390,0); buffer(raw).putLong(0x208,0x4003f8); reject(raw,0x400380,8);
        raw=fixture(8,0x400390,0); buffer(raw).putLong(0x230,7); reject(raw,0x400380,8);
        raw=fixture(8,0x400390,0); buffer(raw).putLong(152,0x30); reject(raw,0x400380,8);
        raw=fixture(8,0x400390,0); buffer(raw).putLong(0x300,0x500000); reject(raw,0x400380,8);
        raw=fixture(8,0x400390,0); buffer(raw).putLong(104,0x500); reject(raw,0x4003fc,8);
        raw=fixture(8,0x400390,0); buffer(raw).putInt(120,1).putLong(128,0).putLong(136,0x400000).putLong(152,0x400).putLong(160,0x400);
        reject(raw,0x400380,8);
        raw=fixture(8,0x400390,0); buffer(raw).putLong(152,0x30); // no DT_NULL within segment
        reject(raw,0x400380,8);
        System.out.println("All "+tests+" ElfRegionAudit checks passed.");
    }
    private static ByteBuffer buffer(byte[] raw) { return ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN); }
    private static byte[] fixture(long type,long site,long addend) {
        byte[] raw=new byte[0x400]; ByteBuffer b=buffer(raw);
        b.putInt(0,0x464c457f); raw[4]=2; raw[5]=1; raw[6]=1;
        b.putShort(16,(short)2).putShort(18,(short)62).putInt(20,1).putLong(32,64);
        b.putShort(52,(short)64).putShort(54,(short)56).putShort(56,(short)2);
        b.putInt(64,1).putLong(72,0).putLong(80,0x400000).putLong(96,0x400).putLong(104,0x400);
        b.putInt(120,2).putLong(128,0x200).putLong(136,0x400200).putLong(152,0x80).putLong(160,0x80);
        b.putLong(0x200,7).putLong(0x208,0x400300);
        b.putLong(0x210,8).putLong(0x218,24);
        b.putLong(0x220,9).putLong(0x228,24);
        b.putLong(0x300,site).putLong(0x308,type).putLong(0x310,addend);
        Arrays.fill(raw,0x380,0x388,(byte)42);
        return raw;
    }
    private static void check(boolean ok,String message) { if(!ok) throw new AssertionError(message); tests++; }
    private static void reject(byte[] raw,long address,long size) {
        try { ElfRegionAudit.audit(raw,address,size); }
        catch(IllegalArgumentException expected) { tests++; return; }
        throw new AssertionError("Malformed/unsupported ELF accepted");
    }
}
