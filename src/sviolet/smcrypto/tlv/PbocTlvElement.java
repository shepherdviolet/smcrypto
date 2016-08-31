package sviolet.smcrypto.tlv;

import sviolet.smcrypto.util.ByteUtils;

import java.math.BigInteger;
import java.util.List;

/**
 * <p>
 *  Tag:</br>
 *  头2个bit表示元素级别
 *  第3个bit表示是否为复合元素
 *  后5个bit, 当全为1时, 表示有两个byte的TAG, 否则只有一个byte
 * </p>
 *
 * Created by S.Violet on 2016/8/31.
 */
public class PbocTlvElement {

    private ElementClass elementClass = ElementClass.Universal;//元素级别
    private boolean constructed = false;//true:复合元素, 内部还包含有TLV单元, false:数据元素, 内部没有TLV单元

    private byte[] tag;//tag数据
    private byte[] length;//length数据
    private int lengthInt = -1;//长度
    private byte[] value;//内容
    private List<PbocTlvElement> subElements;//子元素

    private PbocTlvElement(){

    }

    /**
     * @return 内容长度
     * @throws IllegalPbocTlvFormatException TLV数据格式错
     */
    public int getLengthInt() throws IllegalPbocTlvFormatException {
        if (lengthInt < 0){
            try {
                if (length.length == 1) {
                    lengthInt = new BigInteger(1, length).intValue();//若长度过长, 则只会取后32bit, 可能会出问题哦
                } else {
                    byte[] lengthActual = new byte[length.length - 1];
                    System.arraycopy(length, 1, lengthActual, 0, lengthActual.length);
                    lengthInt = new BigInteger(1, lengthActual).intValue();//若长度过长, 则只会取后32bit, 可能会出问题哦
                }
            } catch (Exception e){
                throw new IllegalPbocTlvFormatException("illegal length bytes, length bytes:" + ByteUtils.bytesToHex(length), e);
            }
        }
        return lengthInt;
    }

    /**
     * @return 元素级别
     */
    public ElementClass getElementClass() {
        return elementClass;
    }

    /**
     * 是否为复合元素
     * @return true:复合元素, 有子元素, false:数据元素
     */
    public boolean isConstructed() {
        return constructed;
    }

    /**
     * @return tag数据
     */
    public byte[] getTag() {
        byte[] result = new byte[tag.length];
        System.arraycopy(tag, 0, result, 0, result.length);
        return result;
    }

    /**
     * @return length数据
     */
    public byte[] getLength() {
        byte[] result = new byte[length.length];
        System.arraycopy(length, 0, result, 0, result.length);
        return result;
    }

    /**
     * @return 内容数据
     */
    public byte[] getValue() {
        if (value == null){
            return null;
        }
        byte[] result = new byte[value.length];
        System.arraycopy(value, 0, result, 0, result.length);
        return result;
    }

    /**
     * @return 子元素
     * @throws IllegalPbocTlvFormatException TLV数据格式错
     */
    public List<PbocTlvElement> getSubElements() throws IllegalPbocTlvFormatException {
        if (!constructed || value == null){
            return null;
        }
        if (subElements == null){
            subElements = PbocTlvParser.parseSub(value);
        }
        return subElements;
    }

    /**
     * 元素级别
     */
    public enum ElementClass{
        Universal,
        Application,
        Context,
        Private
    }

    /*************************************************************************************************
     * create from bytes
     */

    /**
     * 解析tlv数据
     */
    static PbocTlvElement createFromBytes(PbocTlvContext context) throws IllegalPbocTlvFormatException {
        if (context.data == null || context.data.length <= 0){
            throw new IllegalPbocTlvFormatException("tlv bytes is null or empty");
        }
        PbocTlvElement element = new PbocTlvElement();

        //parse tag
        byte tag = context.data[context.offset++];
        element.elementClass = parseTagToElementClass(tag);
        element.constructed = isTagConstructed(tag);
        if (isTagDoubleBytes(tag)){
            if (context.data.length <= context.offset){
                throw new IllegalPbocTlvFormatException("illegal tlv bytes, length is " + context.data.length + ", but it's double bytes tag, tlv bytes:" + ByteUtils.bytesToHex(context.data));
            }
            element.tag = new byte[]{tag, context.data[context.offset++]};
        } else {
            element.tag = new byte[]{tag};
        }

        //parse length
        if (context.data.length <= context.offset){
            throw new IllegalPbocTlvFormatException("illegal tlv bytes, length is " + context.data.length + ", missing length, tlv bytes:" + ByteUtils.bytesToHex(context.data));
        }
        byte firstLength = context.data[context.offset++];
        if ((firstLength & 0x80) == 0){
            element.length = new byte[]{firstLength};
        }else{
            int lengthLength = firstLength & 0x7F;
            if (context.data.length < context.offset + lengthLength){
                throw new IllegalPbocTlvFormatException("illegal tlv bytes, length is " + context.data.length + ", missing expanded length, tlv bytes:" + ByteUtils.bytesToHex(context.data));
            }
            element.length = new byte[lengthLength + 1];
            element.length[0] = firstLength;
            System.arraycopy(context.data, context.offset, element.length, 1, lengthLength);
            context.offset += lengthLength;
        }

        int length = element.getLengthInt();
        if (length <= 0){
            return element;
        }
        if (context.data.length < context.offset + length){
            throw new IllegalPbocTlvFormatException("illegal tlv bytes, tlv bytes length is " + context.data.length + ", but value length > tlv bytes length, tlv bytes:" + ByteUtils.bytesToHex(context.data));
        }
        element.value = new byte[length];
        System.arraycopy(context.data, context.offset, element.value, 0, element.value.length);
        context.offset += length;

        return element;
    }

    private static ElementClass parseTagToElementClass(byte tag) {
        int elementClassInt = tag & 0xC0;
        switch (elementClassInt){
            case 0x00:
                return ElementClass.Universal;
            case 0x40:
                return ElementClass.Application;
            case 0x80:
                return ElementClass.Context;
            case 0xC0:
                return ElementClass.Private;
            default:
                throw new RuntimeException("undefined element class, tag:" + ByteUtils.bytesToHex(new byte[]{tag}));
        }
    }

    private static boolean isTagConstructed(byte tag){
        if ((tag & 0x20) > 0){
            return true;
        }
        return false;
    }

    private static boolean isTagDoubleBytes(byte tag){
        if ((tag & 0x1F) == 0x1F){
            return true;
        }
        return false;
    }

}
