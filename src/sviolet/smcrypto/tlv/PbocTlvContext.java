package sviolet.smcrypto.tlv;

/**
 * TLV解析上下文
 *
 * Created by S.Violet on 2016/8/31.
 */
class PbocTlvContext {

    byte[] data;
    int offset = 0;

    PbocTlvContext(byte[] data) {
        this.data = data;
    }

    boolean hasNext() throws IllegalPbocTlvFormatException {
        if (data == null || data.length <= 0){
            throw new IllegalPbocTlvFormatException("tlv bytes is null or empty");
        }
        if (data.length > offset){
            return true;
        }
        return false;
    }

}
