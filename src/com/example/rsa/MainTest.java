package com.example.rsa;


import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Created by Administrator on 2017/11/11 0011.
 */
public class MainTest {

    static String content = "开票平台 - 签名验签工具";
    static int keySize = 1024;


    /**
     * @param args
     * @throws Exception
     */
    public static  void main(String[] args) throws Exception{

        MainTest test = new MainTest();
        //自测，自己生成签名自己验签
        test.verifyOtherSelfSign();

        //测试验证其他系统的签名
        test.verifyotherSystemSign();
    }

    /**
     * @throws Exception
     */
    public void verifyOtherSelfSign() throws Exception{

        //自己签名自己校验
        KeyPair keyPair = Signature.genKeyPair(keySize);
        String publicKeyString  = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKeyString  = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        String sign = Signature.sign(content, privateKeyString, Signature.SIGN_ALGORITHMS);
        boolean result = Signature.verify(content, sign, publicKeyString, Signature.SIGN_ALGORITHMS);
        System.out.println("RSA  原文： " + content);
        System.out.println("RSA  私钥： " + privateKeyString);
        System.out.println("RSA  签名： " + sign);
        System.out.println("RSA  公钥： " + publicKeyString);
        System.out.println("RSA  验签结果:" + result);

        sign = Signature.sign(content, privateKeyString, Signature.SIGN_ALGORITHM256);
        result = Signature.verify(content, sign, publicKeyString, Signature.SIGN_ALGORITHM256);
        System.out.println("RSA256  原文： " + content);
        System.out.println("RSA256  私钥： " + privateKeyString);
        System.out.println("RSA256  签名： " + sign);
        System.out.println("RSA256  公钥： " + publicKeyString);
        System.out.println("RSA256  验签结果:" + result);
    }

    /**
     * 检验其他系统的签名
     * @throws Exception
     */
    public void verifyotherSystemSign() throws Exception{
        String sign = "ISB4Cb3Bn+o0631JrMhgL/Jo+qF1h20hqzfi4h/Lv+8rOyVfnZXuLOZEl2Mt/k5BfgMttR+7FBzqNcdhia4LtSS5F3YonOHDJaMpclDhCpk3Z5eFTexbehoY3vwzE0CHeKN1Q4XY+LChV1yhB+cYmUALI9Ee5KHBFZJUZ/9R1CQ=";
        String publicKeyString = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCoAg7HbZ08BYaMJDP9n9qlz7f8BI8WBF7S5dXRm9wwIxftLieRn+rTUm6kE/3IX8+Cao6d9Abr1VRCE9Ln3yl1U0Oic69SNSfYgVzJG0O0B/JvQVtT8FghnFu5UnphpSYbPbxXu6ErPPN4extovc8TQab6fUxLQBKvXUJOicOe6wIDAQAB";
        boolean result = Signature.verify(content, sign, publicKeyString, Signature.SIGN_ALGORITHMS);
        System.out.println("RSA  其他系统验签结果:: " + result);

        sign = "h7VnNPIqJmFpCaK7qGA8Q2CLoc7X0Uet+jNIA2ScuWLN42rWKkdbXgWOK7uuF4kUyUAgQrfqlmXiTaFad2bgu6hG2iasA3IYXKNsDCMM9yWRTj6qaDzApomWx9QXc0yTQ+hWaYPfWtKLYfeakc7Qk1pVrvYm+74+h2WS1Q2R5AoDlh7MbHkSDKI1ufQDx5gEJmHoA/hAto1n4KzOuzK6BWlWImIdjMQZT2i3NDYLppSWr5ucJH1xKw/iWpvrBrCYhEB+YpkdWjCzxctDdWA8LjvPjQDNbaYFpayW+tNKGFRKMXcNk0M4frfEpHzASodWxsmdR1votJC25mRisfvtNw==";
        publicKeyString = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwcFfBmHC5C+VMr1XKGUrfNrOtXjAX8Y8o46B2gQ2EuEbwF7RhUFBKLMDF0rM6xRpeZVv9mjA/9m6l8U1E7hpGowBNT55EJzlh9OJIsgzjlGiNCpObXALivjPC+IgX5KvMnxxLYAvXtRN+aFoVJplJkiav5mpQT9N3EnnfQHFSxdko8WiQT1O7KMm8Z0WFcKMV4YJGN8hc9wR8+97gQRJ2bNNdsRShabjE6t9Y8EnAWAHzgX12E2gAwc6eF1kN7VRUd+HW2fAH21IGGNav5bm3iJcsQBiYEszGZV7J3oNvGf99aNxFbyW7iNK3dl5RhiahTqOD9neiKbWJGP4lGz9fwIDAQAB";
        result = Signature.verify(content, sign, publicKeyString, Signature.SIGN_ALGORITHM256);
        System.out.println("RSA256  其他系统验签结果:: " + result);

    }
}
