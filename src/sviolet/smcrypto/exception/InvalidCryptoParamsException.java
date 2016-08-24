package sviolet.smcrypto.exception;

/**
 * 加密参数无效
 *
 * Created by S.Violet on 2016/8/23.
 */
public class InvalidCryptoParamsException extends RuntimeException {

    public InvalidCryptoParamsException(String message) {
        super(message);
    }

    public InvalidCryptoParamsException(String message, Throwable cause) {
        super(message, cause);
    }
}
