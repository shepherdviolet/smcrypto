package sviolet.smcrypto.tlv;

/**
 * 非法的TLV数据
 *
 * Created by S.Violet on 2016/8/31.
 */
public class IllegalPbocTlvFormatException extends Exception {

    public IllegalPbocTlvFormatException(String message) {
        super(message);
    }

    public IllegalPbocTlvFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
