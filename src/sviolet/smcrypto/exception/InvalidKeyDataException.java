package sviolet.smcrypto.exception;

/**
 * 秘钥数据格式错误
 *
 * Created by S.Violet on 2016/8/23.
 */
public class InvalidKeyDataException extends Exception {

    public InvalidKeyDataException(String message) {
        super(message);
    }

    public InvalidKeyDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
