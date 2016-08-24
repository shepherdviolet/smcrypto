package sviolet.smcrypto.sm2;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import sviolet.smcrypto.exception.InvalidCryptoDataException;
import sviolet.smcrypto.exception.InvalidCryptoParamsException;
import sviolet.smcrypto.exception.InvalidKeyException;
import sviolet.smcrypto.exception.InvalidSignDataException;
import sviolet.smcrypto.sm3.SM3Digest;
import sviolet.smcrypto.util.Util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Enumeration;

/**
 * SM2加密器
 * <p>
 * Created by S.Violet on 2016/8/22.
 */
public class SM2Cipher {

    /**
     * SM2的ECC椭圆曲线参数
     */
    private static final BigInteger SM2_ECC_P = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger SM2_ECC_A = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
    private static final BigInteger SM2_ECC_B = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
    private static final BigInteger SM2_ECC_N = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
    private static final BigInteger SM2_ECC_GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    private static final BigInteger SM2_ECC_GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);

    //测试曲线
//    private static final BigInteger SM2_ECC_P = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
//    private static final BigInteger SM2_ECC_A = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
//    private static final BigInteger SM2_ECC_B = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
//    private static final BigInteger SM2_ECC_N = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
//    private static final BigInteger SM2_ECC_GX = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
//    private static final BigInteger SM2_ECC_GY = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);

    private ECCurve.Fp curve;//ECC曲线
    private ECPoint.Fp pointG;//基点
    private ECKeyPairGenerator keyPairGenerator;//密钥对生成器
    private Type type;//密文格式

    private ECPoint alternateKeyPoint;
    private SM3Digest alternateKeyDigest;
    private SM3Digest c3Digest;
    private int alternateKeyCount;
    private byte alternateKey[];
    private byte alternateKeyOff;

    /**
     * 默认椭圆曲线参数的SM2加密器
     *
     * @param type 密文格式
     */
    public SM2Cipher(Type type) {
        this(
                new SecureRandom(),
                type
        );
    }

    /**
     * 默认椭圆曲线参数的SM2加密器
     *
     * @param secureRandom 秘钥生成随机数
     * @param type         密文格式
     */
    public SM2Cipher(SecureRandom secureRandom, Type type) {
        this(
                secureRandom,
                type,
                SM2_ECC_P,
                SM2_ECC_A,
                SM2_ECC_B,
                SM2_ECC_N,
                SM2_ECC_GX,
                SM2_ECC_GY
        );
    }

    /**
     * 默认椭圆曲线参数的SM2加密器
     *
     * @param secureRandom 秘钥生成随机数
     * @param type         密文格式
     * @param eccP         p
     * @param eccA         a
     * @param eccB         b
     * @param eccN         n
     * @param eccGx        gx
     * @param eccGy        gy
     */
    public SM2Cipher(SecureRandom secureRandom, Type type, BigInteger eccP, BigInteger eccA, BigInteger eccB, BigInteger eccN, BigInteger eccGx, BigInteger eccGy) {

        if (type == null) {
            throw new InvalidCryptoParamsException("[SM2]type of the SM2Cipher is null");
        }

        if (eccP == null || eccA == null || eccB == null || eccN == null || eccGx == null || eccGy == null) {
            throw new InvalidCryptoParamsException("[SM2]ecc params of the SM2Cipher is null");
        }

        if (secureRandom == null) {
            secureRandom = new SecureRandom();
        }

        this.type = type;

        //曲线
        ECFieldElement.Fp gxFieldElement = new ECFieldElement.Fp(eccP, eccGx);
        ECFieldElement.Fp gyFieldElement = new ECFieldElement.Fp(eccP, eccGy);
        this.curve = new ECCurve.Fp(eccP, eccA, eccB);

        //密钥对生成器
        this.pointG = new ECPoint.Fp(curve, gxFieldElement, gyFieldElement);
        ECDomainParameters domainParams = new ECDomainParameters(curve, pointG, eccN);
        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(domainParams, secureRandom);
        this.keyPairGenerator = new ECKeyPairGenerator();
        this.keyPairGenerator.init(keyGenerationParams);

    }

    /**
     * @return 产生SM2公私钥对(随机)
     */
    public KeyPair generateKeyPair() {
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters) keyPair.getPublic();
        BigInteger privateKey = privateKeyParams.getD();
        ECPoint publicKey = publicKeyParams.getQ();
        return new KeyPair(privateKey.toByteArray(), publicKey.getEncoded());
    }

    /**
     * SM2加密
     *
     * @param publicKey 公钥
     * @param data      数据
     */
    public byte[] encrypt(byte[] publicKey, byte[] data) {
        if (publicKey == null || publicKey.length == 0) {
            throw new InvalidCryptoParamsException("[SM2:Encrypt]key is null");
        }

        if (data == null || data.length == 0) {
            return null;
        }

        //C2位数据域
        byte[] c2 = new byte[data.length];
        System.arraycopy(data, 0, c2, 0, data.length);

        ECPoint keyPoint = curve.decodePoint(publicKey);

        AsymmetricCipherKeyPair generatedKey = keyPairGenerator.generateKeyPair();
        ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters) generatedKey.getPrivate();
        ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters) generatedKey.getPublic();
        BigInteger privateKey = privateKeyParams.getD();
        ECPoint c1 = publicKeyParams.getQ();
        this.alternateKeyPoint = keyPoint.multiply(privateKey);
        reset();

        this.c3Digest.update(c2);
        for (int i = 0; i < c2.length; i++) {
            if (alternateKeyOff >= alternateKey.length) {
                nextKey();
            }
            c2[i] ^= alternateKey[alternateKeyOff++];
        }

        byte p[] = Util.byteConvert32Bytes(alternateKeyPoint.getY().toBigInteger());
        this.c3Digest.update(p);
        byte[] c3 = this.c3Digest.doFinal();
        reset();

        byte[] result = new byte[97 + c2.length];
        switch (type) {
            case C1C2C3:
                System.arraycopy(c1.getEncoded(), 0, result, 0, 65);//C1:Point, 标志位1byte, 数据64byte
                System.arraycopy(c2, 0, result, 65, c2.length);//C2:加密数据
                System.arraycopy(c3, 0, result, 65 + c2.length, 32);//C3:摘要 32byte
                break;
            case C1C3C2:
                System.arraycopy(c1.getEncoded(), 0, result, 0, 65);//C1:Point, 标志位1byte, 数据64byte
                System.arraycopy(c3, 0, result, 65, 32);//C3:摘要 32byte
                System.arraycopy(c2, 0, result, 97, c2.length);//C2:加密数据
                break;
            default:
                throw new InvalidCryptoParamsException("[SM2:Encrypt]invalid type(" + String.valueOf(type) + ")");
        }

        return result;
    }

    /**
     * SM2解密
     *
     * @param privateKey 私钥
     * @param data       数据
     */
    public byte[] decrypt(byte[] privateKey, byte[] data) throws InvalidKeyException, InvalidCryptoDataException {
        if (privateKey == null || privateKey.length == 0) {
            throw new InvalidCryptoParamsException("[SM2:Decrypt]key is null");
        }

        if (data == null || data.length == 0) {
            return null;
        }

        if (data.length <= 97) {
            throw new InvalidCryptoDataException("[SM2:Decrypt]invalid encrypt data, length <= 97 bytes");
        }

        byte[] c1 = new byte[65];
        byte[] c2 = new byte[data.length - 97];
        byte[] c3 = new byte[32];
        switch (type) {
            case C1C2C3:
                System.arraycopy(data, 0, c1, 0, c1.length);//C1:Point, 标志位1byte, 数据64byte
                System.arraycopy(data, c1.length, c2, 0, c2.length);//C2:加密数据
                System.arraycopy(data, c1.length + c2.length, c3, 0, c3.length);//C3:摘要 32byte
                break;
            case C1C3C2:
                System.arraycopy(data, 0, c1, 0, c1.length);//C1:Point, 标志位1byte, 数据64byte
                System.arraycopy(data, c1.length, c3, 0, c3.length);//C3:摘要 32byte
                System.arraycopy(data, c1.length + c3.length, c2, 0, c2.length);//C2:加密数据
                break;
            default:
                throw new InvalidCryptoParamsException("[SM2:Decrypt]invalid type(" + String.valueOf(type) + ")");
        }

        BigInteger decryptKey = new BigInteger(1, privateKey);
        ECPoint c1Point = curve.decodePoint(c1);
        this.alternateKeyPoint = c1Point.multiply(decryptKey);
        reset();

        for (int i = 0; i < c2.length; i++) {
            if (alternateKeyOff >= alternateKey.length) {
                nextKey();
            }
            c2[i] ^= alternateKey[alternateKeyOff++];
        }

        this.c3Digest.update(c2, 0, c2.length);

        byte p[] = Util.byteConvert32Bytes(alternateKeyPoint.getY().toBigInteger());
        this.c3Digest.update(p, 0, p.length);
        byte[] verifyC3 = this.c3Digest.doFinal();

        if (!Arrays.equals(verifyC3, c3)) {
            throw new InvalidKeyException("[SM2:Decrypt]invalid key, c3 is not match");
        }

        reset();

        //返回解密结果
        return c2;
    }

    private void reset() {
        this.alternateKeyDigest = new SM3Digest();
        this.c3Digest = new SM3Digest();

        byte p[] = Util.byteConvert32Bytes(alternateKeyPoint.getX().toBigInteger());
        this.alternateKeyDigest.update(p);
        this.c3Digest.update(p, 0, p.length);

        p = Util.byteConvert32Bytes(alternateKeyPoint.getY().toBigInteger());
        this.alternateKeyDigest.update(p);
        this.alternateKeyCount = 1;
        nextKey();
    }

    private void nextKey() {
        SM3Digest digest = new SM3Digest(this.alternateKeyDigest);
        digest.update((byte) (alternateKeyCount >> 24 & 0xff));
        digest.update((byte) (alternateKeyCount >> 16 & 0xff));
        digest.update((byte) (alternateKeyCount >> 8 & 0xff));
        digest.update((byte) (alternateKeyCount & 0xff));
        alternateKey = digest.doFinal();
        this.alternateKeyOff = 0;
        this.alternateKeyCount++;
    }

    /**
     * 签名
     * @param userId 用户ID
     * @param privateKey 私钥
     * @param sourceData 数据
     * @return 签名数据{r, s}
     */
    public BigInteger[] sign(byte[] userId, byte[] privateKey, byte[] sourceData) {
        if (privateKey == null || privateKey.length == 0) {
            throw new InvalidCryptoParamsException("[SM2:sign]key is null");
        }

        if (sourceData == null || sourceData.length == 0) {
            return null;
        }

        //私钥, 私钥和基点生成秘钥点
        BigInteger key = new BigInteger(privateKey);
        ECPoint keyPoint = pointG.multiply(key);

        //Z
        SM3Digest digest = new SM3Digest();
        byte[] z = getZ(userId, keyPoint);

        //对数据做摘要
        digest.update(z, 0, z.length);
        digest.update(sourceData);
        byte[] digestData = digest.doFinal();

        //签名数据{r, s}
        return signInner(digestData, key, keyPoint);
    }

    /**
     * 签名(ASN.1编码)
     * @param userId 用户ID
     * @param privateKey 私钥
     * @param sourceData 数据
     * @return 签名数据 byte[] ASN.1编码
     */
    public byte[] signASN1(byte[] userId, byte[] privateKey, byte[] sourceData){
        BigInteger[] signData = sign(userId, privateKey, sourceData);
        //签名数据序列化
        DERInteger derR = new DERInteger(signData[0]);//r
        DERInteger derS = new DERInteger(signData[1]);//s
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(derR);
        vector.add(derS);
        DERObject sign = new DERSequence(vector);
        return sign.getDEREncoded();
    }

    /**
     * 验签
     * @param userId 用户ID
     * @param publicKey 公钥
     * @param sourceData 数据
     * @param signR 签名数据r
     * @param signS 签名数据s
     * @return true:签名有效
     */
    public boolean verifySign(byte[] userId, byte[] publicKey, byte[] sourceData, BigInteger signR, BigInteger signS){
        if (publicKey == null || publicKey.length == 0) {
            throw new InvalidCryptoParamsException("[SM2:verifySign]key is null");
        }

        if (sourceData == null || sourceData.length == 0 || signR == null || signS == null) {
            return false;
        }

        //公钥
        ECPoint key = curve.decodePoint(publicKey);

        //Z
        SM3Digest digest = new SM3Digest();
        byte[] z = getZ(userId, key);

        //对数据摘要
        digest.update(z, 0, z.length);
        digest.update(sourceData, 0, sourceData.length);
        byte[] digestData = digest.doFinal();

        //验签
        return signR.equals(verifyInner(digestData, key, signR, signS));
    }

    /**
     * 验签(ASN.1编码签名)
     * @param userId 用户ID
     * @param publicKey 公钥
     * @param sourceData 数据
     * @param signData 签名数据(ASN.1编码)
     * @return true 签名有效
     * @throws InvalidSignDataException ASN.1编码无效
     */
    @SuppressWarnings("unchecked")
    public boolean verifySignASN1(byte[] userId, byte[] publicKey, byte[] sourceData, byte[] signData) throws InvalidSignDataException{

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(signData);
        ASN1InputStream asn1InputStream = new ASN1InputStream(byteArrayInputStream);
        Enumeration<DERInteger> signObj;
        try {
            DERObject derObj = asn1InputStream.readObject();
            signObj = ((ASN1Sequence) derObj).getObjects();
        } catch (IOException e){
            throw new InvalidSignDataException("[SM2:verifySign]invalid sign data (ASN.1)", e);
        }
        BigInteger r = signObj.nextElement().getValue();
        BigInteger s = signObj.nextElement().getValue();

        //验签
        return verifySign(userId, publicKey, sourceData, r, s);
    }

    private byte[] getZ(byte[] userId, ECPoint userKey) {
        SM3Digest digest = new SM3Digest();

        int len = userId.length * 8;
        digest.update((byte) (len >> 8 & 0xFF));
        digest.update((byte) (len & 0xFF));
        digest.update(userId);

        byte[] p = Util.byteConvert32Bytes(SM2_ECC_A);
        digest.update(p);

        p = Util.byteConvert32Bytes(SM2_ECC_B);
        digest.update(p);

        p = Util.byteConvert32Bytes(SM2_ECC_GX);
        digest.update(p);

        p = Util.byteConvert32Bytes(SM2_ECC_GY);
        digest.update(p);

        p = Util.byteConvert32Bytes(userKey.getX().toBigInteger());
        digest.update(p);

        p = Util.byteConvert32Bytes(userKey.getY().toBigInteger());
        digest.update(p);

        return digest.doFinal();
    }

    /**
     * @return {r, s}
     */
    private BigInteger[] signInner(byte[] digestData, BigInteger key, ECPoint keyPoint) {
        BigInteger e = new BigInteger(1, digestData);
        BigInteger k;
        ECPoint kp;
        BigInteger r;
        BigInteger s;
        do {
            do {
                //正式环境
                AsymmetricCipherKeyPair keypair = keyPairGenerator.generateKeyPair();
                ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keypair.getPrivate();
                ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keypair.getPublic();
                k = privateKey.getD();
                kp = publicKey.getQ();

                //国密规范测试 随机数k
//                String kS = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
//                k = new BigInteger(kS, 16);
//                kp = this.pointG.multiply(k);

                //r
                r = e.add(kp.getX().toBigInteger());
                r = r.mod(SM2_ECC_N);
            } while (r.equals(BigInteger.ZERO) || r.add(k).equals(SM2_ECC_N));

            //(1 + dA)~-1
            BigInteger da_1 = key.add(BigInteger.ONE);
            da_1 = da_1.modInverse(SM2_ECC_N);

            //s
            s = r.multiply(key);
            s = k.subtract(s).mod(SM2_ECC_N);
            s = da_1.multiply(s).mod(SM2_ECC_N);
        } while (s.equals(BigInteger.ZERO));

        return new BigInteger[]{r, s};
    }

    private BigInteger verifyInner(byte digestData[], ECPoint userKey, BigInteger r, BigInteger s) {
        BigInteger e = new BigInteger(1, digestData);
        BigInteger t = r.add(s).mod(SM2_ECC_N);
        if (t.equals(BigInteger.ZERO)) {
            return null;
        } else {
            ECPoint x1y1 = pointG.multiply(s);
            x1y1 = x1y1.add(userKey.multiply(t));
            return e.add(x1y1.getX().toBigInteger()).mod(SM2_ECC_N);
        }
    }

    public static class KeyPair {

        private byte[] privateKey;
        private byte[] publicKey;

        private KeyPair(byte[] privateKey, byte[] publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public byte[] getPrivateKey() {
            return privateKey;
        }

        public byte[] getPublicKey() {
            return publicKey;
        }
    }

    public enum Type {
        C1C2C3,
        C1C3C2
    }

}
