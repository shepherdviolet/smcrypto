package test;

import sviolet.smcrypto.SM2Cipher;
import sviolet.smcrypto.SM3Digest;
import sviolet.smcrypto.exception.InvalidCryptoDataException;
import sviolet.smcrypto.exception.InvalidKeyDataException;
import sviolet.smcrypto.exception.InvalidKeyException;
import sviolet.smcrypto.exception.InvalidSignDataException;
import sviolet.smcrypto.util.ByteUtils;

import java.io.IOException;


public class TestCase {

    public static void main(String[] args) throws InvalidKeyException, InvalidCryptoDataException, InvalidSignDataException, InvalidKeyDataException, IOException {
        common();
    }

    private static String sm3content = "64055D80810171DCE32D71773ECFDC803203539DB5677401DDD6A2B538D0652978479B5BE524FE809CB35499BDCC4C8FC1081CB2E09BCB4458828C5168BE329D";
    private static String sm2content = "hello world !!~";
    private static String sm2publickey = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";
    private static String ms2privatekey = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";

    private static void common() throws InvalidKeyDataException, InvalidKeyException, InvalidCryptoDataException, InvalidSignDataException {
        SM3Digest digest = new SM3Digest();
        digest.update(ByteUtils.hexToBytes(sm3content));
        byte[] sm3result = digest.doFinal();
        System.out.println("sm3:" + ByteUtils.bytesToHex(sm3result));

        SM2Cipher cipher = new SM2Cipher(SM2Cipher.Type.C1C3C2);
        byte[] sm2result = cipher.encrypt(ByteUtils.hexToBytes(sm2publickey), sm2content.getBytes());
        System.out.println("sm2 encrypt:" + ByteUtils.bytesToHex(sm2result));
        byte[] sm2result2 = cipher.decrypt(ByteUtils.hexToBytes(ms2privatekey), ByteUtils.hexToBytes(ByteUtils.bytesToHex(sm2result)));
        System.out.println("sm2 decrypt:" + new String(sm2result2));

        SM2Cipher.KeyPair keyPair = cipher.generateKeyPair();
        System.out.println("sm2 gen key private:" + ByteUtils.bytesToHex(keyPair.getPrivateKey()));
        System.out.println("sm2 gen key public:" + ByteUtils.bytesToHex(keyPair.getPublicKey()));

        String plainText = "message digest";
        byte[] sourceData = plainText.getBytes();

        // 国密规范测试用户ID
        String userId = "ALICE123@YAHOO.COM";

        byte[] c = cipher.signToBytes(userId.getBytes(), ByteUtils.hexToBytes(ms2privatekey), sourceData);
        System.out.println("sign: " + ByteUtils.bytesToHex(c));

        boolean vs = cipher.verifySignByBytes(userId.getBytes(), ByteUtils.hexToBytes(sm2publickey), ByteUtils.hexToBytes(ByteUtils.bytesToHex(sourceData)), ByteUtils.hexToBytes(ByteUtils.bytesToHex(c)));
        System.out.println("验签结果: " + vs);
    }

}
