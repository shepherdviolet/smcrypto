package sviolet.smcrypto.tlv;

import sviolet.smcrypto.util.ByteUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * PBOC标准TLV解析器
 *
 * Created by S.Violet on 2016/8/31.
 */
public class PbocTlvParser {

    /**
     * 解析PBOC标准的TLV数据
     * @param tlvData TLV数据
     * @return 根节点元素
     * @throws IllegalPbocTlvFormatException TLV数据格式错误
     */
    public static PbocTlvElement parse(byte[] tlvData) throws IllegalPbocTlvFormatException {
        PbocTlvContext context = new PbocTlvContext(tlvData);
        PbocTlvElement element = PbocTlvElement.createFromBytes(context);
        if (context.hasNext()){
            throw new IllegalPbocTlvFormatException("illegal tlv bytes, found redundant data after one element parsed, tlv data:" + ByteUtils.bytesToHex(tlvData) + ", offset:" + context.offset);
        }
        return element;
    }

    /**
     * 内部使用, 解析自元素
     */
    static List<PbocTlvElement> parseSub(byte[] tlvData) throws IllegalPbocTlvFormatException {
        List<PbocTlvElement> list = new ArrayList<>();
        PbocTlvContext context = new PbocTlvContext(tlvData);
        while (context.hasNext()){
            list.add(PbocTlvElement.createFromBytes(context));
        }
        return list;
    }

}
