package sviolet.smcrypto.exception;

/**
 * 加密数据无效
 *
 * Created by S.Violet on 2016/8/23.
 */
public class InvalidCryptoDataException extends Exception {

    public InvalidCryptoDataException(String message) {
        super(message);
    }

    public InvalidCryptoDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
