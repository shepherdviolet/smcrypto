package test;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import sviolet.smcrypto.SM2Cipher;
import sviolet.smcrypto.exception.InvalidCertificateException;
import sviolet.smcrypto.exception.InvalidKeyDataException;
import sviolet.smcrypto.exception.InvalidSignDataException;
import sviolet.smcrypto.tlv.IllegalPbocTlvFormatException;
import sviolet.smcrypto.util.Base64Utils;
import sviolet.smcrypto.util.ByteUtils;
import sviolet.smcrypto.util.CertificateUtils;

import java.io.IOException;

/**
 * Created by S.Violet on 2016/8/24.
 */
public class CertTest {

    public static void main(String[] args) throws IOException, InvalidCertificateException, InvalidKeyDataException, InvalidSignDataException, IllegalPbocTlvFormatException {
        certVerify();
        System.out.println("\n\n");
        dataVerify();
    }

    //证书验证的证书
    private static final String certData = "MIICaDCCAgygAwIBAgIJAK8ocl2Y0zFDMAwGCCqBHM9VAYN1BQAwfTELMAkGA1UEBgwCY24xCzAJBgNVBAgMAmJqMQswCQYDVQQHDAJiajEPMA0GA1UECgwGdG9wc2VjMQ8wDQYDVQQLDAZ0b3BzZWMxETAPBgNVBAMMCFRvcHNlY0NBMR8wHQYJKoZIhvcNAQkBDBBiakB0b3BzZWMuY29tLmNuMB4XDTEyMDYyNDA3NTQzOVoXDTMyMDYyMDA3NTQzOVowfTELMAkGA1UEBgwCY24xCzAJBgNVBAgMAmJqMQswCQYDVQQHDAJiajEPMA0GA1UECgwGdG9wc2VjMQ8wDQYDVQQLDAZ0b3BzZWMxETAPBgNVBAMMCFRvcHNlY0NBMR8wHQYJKoZIhvcNAQkBDBBiakB0b3BzZWMuY29tLmNuMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE1pwvHuw7+2uVswwoCFx3sSXXepw5Ul2BkHaPN9ayBbWJ3NMWu+fYmp3CGRfxd5nmmFMfXm4+EL0xNwslnD+Bw6NzMHEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUjl2QNHhYuqrYcNi9+6aoXntWO2QwHwYDVR0jBBgwFoAUjl2QNHhYuqrYcNi9+6aoXntWO2QwCwYDVR0PBAQDAgEGMBEGCWCGSAGG+EIBAQQEAwIAVzAMBggqgRzPVQGDdQUAA0gAMEUCIQCGqTACsUVb7KXmi8E5pqJtyWpKj1Mm0vPokvH6ondQKwIgFH5vrHQjncD1e9avYQBSF9fxplgZ/tdU9nxDgh2HnRU=";

    private static void certVerify() throws IOException, InvalidSignDataException, InvalidKeyDataException, IllegalPbocTlvFormatException {
        byte[] certBytes = Base64Utils.decode(certData);

        System.out.println("证书数据:" + ByteUtils.bytesToHex(certBytes));
        //自签名根证书
        X509CertificateStructure certInfo = CertificateUtils.parseX509(certBytes);
        System.out.println("证书版本:" + certInfo.getVersion());
        System.out.println("序列号:" + certInfo.getSerialNumber().getValue().toString(16));
        System.out.println("算法标识:" + certInfo.getSignatureAlgorithm().getObjectId().getId());
        System.out.println("签发者:" + certInfo.getIssuer());
        System.out.println("开始时间:" + certInfo.getStartDate().getTime());
        System.out.println("结束时间:" + certInfo.getEndDate().getTime());
        System.out.println("主体名:" + certInfo.getSubject());
        System.out.println("签名值:" + ByteUtils.bytesToHex(certInfo.getSignature().getBytes()));

        SubjectPublicKeyInfo publicInfo = certInfo.getSubjectPublicKeyInfo();
        System.out.println("主体标识符:" + publicInfo.getAlgorithmId().getObjectId().getId());
        System.out.println("主体公钥值:" + ByteUtils.bytesToHex(publicInfo.getPublicKeyData().getBytes()));

        //验签无效, 因为国密证书验签是还需要填充数据, 并不是简单的将前面内容进行验签
        SM2Cipher cipher = new SM2Cipher(SM2Cipher.Type.C1C3C2);
        System.out.println(cipher.verifyCertByPublicKey(certBytes, publicInfo.getPublicKeyData().getBytes()));//根证书用自己的公钥验证
    }

    //数据验签的证书
    private static final String certData2 = "MIICQDCCAeWgAwIBAgIQG2THdO0arf/KaLKoTVlCOzAMBggqgRzPVQGDdQUAMB8xEDAOBgNVBAMMB1NNMlJPT1QxCzAJBgNVBAYTAkNOMB4XDTE0MDYxODEzNTgzNVoXDTE2MDYxODEzNTgzNVowZTEiMCAGCSqGSIb3DQEJARYTam9ubGxlbkBob3RtYWlsLmNvbTEPMA0GA1UEBwwG6ZW/5rKZMQ8wDQYDVQQIDAbmuZbljZcxCzAJBgNVBAYTAkNOMRAwDgYDVQQDDAdKb25sbGVuMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEXLAuT39XB5LJmTprFiGLPfqZl5tyGm1n9oXSVDrGRP2RfQRJOqD6cH6PEvmGhM1ydJv0iQMg2mvh6PjAlm58W6OBujCBtzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQstXX3UIwlBK9k70GJYGM8mjG6gTAfBgNVHSMEGDAWgBQ/LpOmNnAJt7mAwIZpsX3cnqlkqjBCBggrBgEFBQcBAQQ2MDQwMgYIKwYBBQUHMAKGJmh0dHA6Ly9sb2NhbGhvc3QvUEtJL2NlcnRzL0RTQVJPT1QuY3J0MA4GA1UdDwEB/wQEAwIE8DATBgNVHSUEDDAKBggrBgEFBQcDAjAMBggqgRzPVQGDdQUAA0cAMEQCIBJO7K/XDt+igzKkWSkbRKZRtQKsS1i2Fmdp2Ar5EEL+AiA759mE/uINaEC7sMXOoqzTzkLCMIHGyLi80j0dG5pjow==";

    private static void dataVerify() throws InvalidCertificateException, InvalidSignDataException, InvalidKeyDataException {
        //数据验签
        String data = "jonllen";
        String sign = "64LTP1CphtWrfHnFB3OMyEuV1+ei5DpBPZY39VeQUb9V6yRYP3SbpAWivrpP1q5j0D8b4xQid4327TK9NvEbrA==";//r + s 格式的签名
        byte[] certBytes = Base64Utils.decode(certData2);
        byte[] signBytes = Base64Utils.decode(sign);
        System.out.println("certBytes:" + ByteUtils.bytesToHex(certBytes));
        System.out.println("signBytes:" + ByteUtils.bytesToHex(signBytes));

        SM2Cipher cipher = new SM2Cipher(SM2Cipher.Type.C1C3C2);
        System.out.println(cipher.verifySignByX509Cert(certBytes, data.getBytes(), signBytes));
    }

}
