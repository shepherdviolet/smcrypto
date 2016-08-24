package sviolet.smcrypto.exception;

/**
 * 秘钥错误
 *
 * Created by S.Violet on 2016/8/23.
 */
public class InvalidKeyException extends Exception {

    public InvalidKeyException(String message) {
        super(message);
    }

    public InvalidKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
