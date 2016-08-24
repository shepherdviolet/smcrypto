package sviolet.smcrypto.exception;

/**
 * 证书无效(格式)
 *
 * Created by S.Violet on 2016/8/23.
 */
public class InvalidCertificateException extends Exception {

    public InvalidCertificateException(String message) {
        super(message);
    }

    public InvalidCertificateException(String message, Throwable cause) {
        super(message, cause);
    }
}
