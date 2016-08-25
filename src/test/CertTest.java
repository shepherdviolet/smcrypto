package test;

import sviolet.smcrypto.exception.InvalidCertificateException;
import sviolet.smcrypto.exception.InvalidKeyDataException;
import sviolet.smcrypto.exception.InvalidSignDataException;
import sviolet.smcrypto.sm2.SM2Cipher;
import sviolet.smcrypto.util.Base64Utils;

import java.io.IOException;

/**
 * Created by S.Violet on 2016/8/24.
 */
public class CertTest {

    private static final String certData = "MIICQDCCAeWgAwIBAgIQG2THdO0arf/KaLKoTVlCOzAMBggqgRzPVQGDdQUAMB8xEDAOBgNVBAMMB1NNMlJPT1QxCzAJBgNVBAYTAkNOMB4XDTE0MDYxODEzNTgzNVoXDTE2MDYxODEzNTgzNVowZTEiMCAGCSqGSIb3DQEJARYTam9ubGxlbkBob3RtYWlsLmNvbTEPMA0GA1UEBwwG6ZW/5rKZMQ8wDQYDVQQIDAbmuZbljZcxCzAJBgNVBAYTAkNOMRAwDgYDVQQDDAdKb25sbGVuMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEXLAuT39XB5LJmTprFiGLPfqZl5tyGm1n9oXSVDrGRP2RfQRJOqD6cH6PEvmGhM1ydJv0iQMg2mvh6PjAlm58W6OBujCBtzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQstXX3UIwlBK9k70GJYGM8mjG6gTAfBgNVHSMEGDAWgBQ/LpOmNnAJt7mAwIZpsX3cnqlkqjBCBggrBgEFBQcBAQQ2MDQwMgYIKwYBBQUHMAKGJmh0dHA6Ly9sb2NhbGhvc3QvUEtJL2NlcnRzL0RTQVJPT1QuY3J0MA4GA1UdDwEB/wQEAwIE8DATBgNVHSUEDDAKBggrBgEFBQcDAjAMBggqgRzPVQGDdQUAA0cAMEQCIBJO7K/XDt+igzKkWSkbRKZRtQKsS1i2Fmdp2Ar5EEL+AiA759mE/uINaEC7sMXOoqzTzkLCMIHGyLi80j0dG5pjow==";

    public static void main(String[] args) throws IOException, InvalidCertificateException, InvalidKeyDataException, InvalidSignDataException {

        String data = "jonllen";
        String sign = "64LTP1CphtWrfHnFB3OMyEuV1+ei5DpBPZY39VeQUb9V6yRYP3SbpAWivrpP1q5j0D8b4xQid4327TK9NvEbrA==";
        byte[] certBytes = Base64Utils.decode(certData);
        byte[] signBytes = Base64Utils.decode(sign);
        System.out.println(ByteUtils.bytesToHex(certBytes));
        System.out.println(ByteUtils.bytesToHex(signBytes));

        SM2Cipher cipher = new SM2Cipher(SM2Cipher.Type.C1C3C2);
        System.out.println(cipher.verifySignByX509Cert(certBytes, data.getBytes(), signBytes));

    }

}
