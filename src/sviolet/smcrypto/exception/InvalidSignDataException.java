package sviolet.smcrypto.exception;

/**
 * 签名数据无效
 *
 * Created by S.Violet on 2016/8/23.
 */
public class InvalidSignDataException extends Exception {

    public InvalidSignDataException(String message) {
        super(message);
    }

    public InvalidSignDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
