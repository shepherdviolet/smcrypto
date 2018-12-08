# smcrypto

* The project is outdated, see https://github.com/shepherdviolet/thistle
* 这个工程不再维护, 使用国密算法签名加密请看下文

# 新项目`thistle-crypto-plus`简介

# 依赖

```gradle

repositories {
    //Thistle in mavenCentral
    mavenCentral()
}
dependencies {
    //Advanced crypto utils
    compile 'com.github.shepherdviolet:thistle-crypto-plus:12.3'
}

```

```maven
    <!-- Advanced crypto utils -->
    <dependency>    
        <groupId>com.github.shepherdviolet</groupId>
        <artifactId>thistle-crypto-plus</artifactId>
        <version>12.3</version> 
    </dependency>
```

# 示例

* https://github.com/shepherdviolet/thistle/blob/master/thistle-crypto-plus/src/test/java/sviolet/thistle/util/crypto/SM2CertTest.java
* https://github.com/shepherdviolet/thistle/blob/master/thistle-crypto-plus/src/test/java/sviolet/thistle/util/crypto/SM2CipherTest.java
* https://github.com/shepherdviolet/thistle/blob/master/thistle-crypto-plus/src/test/java/sviolet/thistle/util/crypto/SM3DigestCipherTest.java
* https://github.com/shepherdviolet/thistle/blob/master/thistle-crypto-plus/src/test/java/sviolet/thistle/util/crypto/SM4CipherTest.java
