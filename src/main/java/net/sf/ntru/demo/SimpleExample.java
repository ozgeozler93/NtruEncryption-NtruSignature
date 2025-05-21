package net.sf.ntru.demo;

import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.NtruEncrypt;
import net.sf.ntru.sign.NtruSign;
import net.sf.ntru.sign.SignatureKeyPair;
import net.sf.ntru.sign.SignatureParameters;

import java.util.Arrays;

public class SimpleExample {

    public static void main(String[] args) {
        encrypt();
        System.out.println();
        sign();
        System.out.println();

        test1_encryptionTiming();
        System.out.println();

        test2_randomness();
        System.out.println();

        test3_parameterComparison();
        System.out.println();

        test8_longMessageTest();
        System.out.println();

        test9_avalancheEffect();
        System.out.println();

        test12_serialEncryptionPerformance();
        System.out.println();

        test4_signatureVerification();
        System.out.println();

        test5_wrongKeyVerification();
        System.out.println();

        test6_messageManipulation();
        System.out.println();

        test7_signatureParameterComparison();
        System.out.println();

        test10_signatureRandomness();
        System.out.println();

        test11_fakeMessageVerification();
    }

    private static void encrypt() {
        System.out.println("NTRU encryption");
        NtruEncrypt ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
        EncryptionKeyPair kp = ntru.generateKeyPair();
        String msg = "Makbule \u00d6zge'nin test mesaj\u0131";
        System.out.println("  Before encryption: " + msg);
        byte[] enc = ntru.encrypt(msg.getBytes(), kp.getPublic());
        byte[] dec = ntru.decrypt(enc, kp);
        System.out.println("  After decryption:  " + new String(dec));
    }

    private static void sign() {
        System.out.println("NTRU signature");
        NtruSign ntru = new NtruSign(SignatureParameters.TEST157);
        SignatureKeyPair kp = ntru.generateKeyPair();
        String msg = "The quick brown fox";
        System.out.println("  Message: " + msg);
        byte[] sig = ntru.sign(msg.getBytes(), kp);
        boolean valid = ntru.verify(msg.getBytes(), sig, kp.getPublic());
        System.out.println("  Signature valid? " + valid);
    }

    private static void test1_encryptionTiming() {
        System.out.println("\ud83d\udccc Test 1 \u2013 \u015eifreleme/De\u015fifreleme S\u00fcresi");
        String msg = "Makbule test \u015fifreleme s\u00fcresi";
        NtruEncrypt ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
        EncryptionKeyPair kp = ntru.generateKeyPair();
        long startEnc = System.nanoTime();
        byte[] enc = ntru.encrypt(msg.getBytes(), kp.getPublic());
        long endEnc = System.nanoTime();
        long startDec = System.nanoTime();
        byte[] dec = ntru.decrypt(enc, kp);
        long endDec = System.nanoTime();
        System.out.println("Mesaj: " + msg);
        System.out.printf("\u015eifreleme s\u00fcresi: %.3f ms%n", (endEnc - startEnc) / 1_000_000.0);
        System.out.printf("\u00c7\u00f6zme s\u00fcresi:     %.3f ms%n", (endDec - startDec) / 1_000_000.0);
        System.out.println("\u00c7\u00f6z\u00fclen mesaj: " + new String(dec));
    }

    private static void test2_randomness() {
        System.out.println("\ud83d\udccc Test 2 \u2013 Rastgelelik Testi");
        String msg = "Makbule rastgelelik testi";
        NtruEncrypt ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
        EncryptionKeyPair kp = ntru.generateKeyPair();
        byte[] enc1 = ntru.encrypt(msg.getBytes(), kp.getPublic());
        byte[] enc2 = ntru.encrypt(msg.getBytes(), kp.getPublic());
        System.out.println("\u015eifreli mesaj 1 boyutu: " + enc1.length);
        System.out.println("\u015eifreli mesaj 2 boyutu: " + enc2.length);
        System.out.println("\u015eifreli \u00e7\u0131kt\u0131lar ayn\u0131 m\u0131?: " + Arrays.equals(enc1, enc2));
    }

    private static void test3_parameterComparison() {
        System.out.println("\ud83d\udccc Test 3 \u2013 Parametre K\u0131yaslamas\u0131");
        String msg = "Parametre k\u0131yaslama testi";
        EncryptionParameters[] paramSet = {
            EncryptionParameters.APR2011_439_FAST,
            EncryptionParameters.APR2011_743
        };
        for (EncryptionParameters params : paramSet) {
            System.out.println("\n\ud83d\udd39 Parametre Seti: " + params.toString());
            NtruEncrypt ntru = new NtruEncrypt(params);
            EncryptionKeyPair kp = ntru.generateKeyPair();
            long t1 = System.nanoTime();
            byte[] enc = ntru.encrypt(msg.getBytes(), kp.getPublic());
            long t2 = System.nanoTime();
            long t3 = System.nanoTime();
            byte[] dec = ntru.decrypt(enc, kp);
            long t4 = System.nanoTime();
            System.out.printf("\u015eifreleme s\u00fcresi: %.3f ms%n", (t2 - t1) / 1_000_000.0);
            System.out.printf("\u00c7\u00f6zme s\u00fcresi:     %.3f ms%n", (t4 - t3) / 1_000_000.0);
            System.out.println("Ciphertext boyutu: " + enc.length + " byte");
            System.out.println("Mesaj do\u011fru \u00e7\u00f6z\u00fcld\u00fc m\u00fc?: " + msg.equals(new String(dec)));
        }
    }

    private static void test8_longMessageTest() {
    	System.out.println("📌 Test 8 – Uzun Mesaj Testi");

    	NtruEncrypt ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
    	EncryptionKeyPair kp = ntru.generateKeyPair();
    	byte[] longMsg = new byte[1000];
    	Arrays.fill(longMsg, (byte) 'A');

    	try {
        	ntru.encrypt(longMsg, kp.getPublic());
        	System.out.println("Uzun mesaj şifrelenebildi (beklenmedik durum)");
    	} catch (net.sf.ntru.exception.NtruException e) {
        	System.out.println("HATA: Uzun mesaj işlenemedi → " + e.getMessage());
    	}
     }


    private static void test9_avalancheEffect() {
        System.out.println("\ud83d\udccc Test 9 \u2013 Avalanche Effect Testi");
        String msg1 = "Makbule";
        String msg2 = "Makbula";
        NtruEncrypt ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
        EncryptionKeyPair kp = ntru.generateKeyPair();
        byte[] enc1 = ntru.encrypt(msg1.getBytes(), kp.getPublic());
        byte[] enc2 = ntru.encrypt(msg2.getBytes(), kp.getPublic());
        int diff = 0;
        for (int i = 0; i < enc1.length; i++) {
            if (enc1[i] != enc2[i]) diff++;
        }
        System.out.println("Farkl\u0131 byte say\u0131s\u0131: " + diff);
        System.out.println("Toplam uzunluk: " + enc1.length);
    }

    private static void test12_serialEncryptionPerformance() {
        System.out.println("\ud83d\udccc Test 12 \u2013 Seri \u015eifreleme Performans\u0131");
        String msg = "Makbule seri test mesaj\u0131";
        NtruEncrypt ntru = new NtruEncrypt(EncryptionParameters.APR2011_439_FAST);
        EncryptionKeyPair kp = ntru.generateKeyPair();
        long totalEnc = 0, totalDec = 0;
        for (int i = 0; i < 100; i++) {
            long t1 = System.nanoTime();
            byte[] enc = ntru.encrypt(msg.getBytes(), kp.getPublic());
            long t2 = System.nanoTime();
            byte[] dec = ntru.decrypt(enc, kp);
            long t3 = System.nanoTime();
            totalEnc += (t2 - t1);
            totalDec += (t3 - t2);
        }
        System.out.printf("Ortalama \u015eifreleme s\u00fcresi: %.3f ms%n", totalEnc / 100_000_000.0);
        System.out.printf("Ortalama \u00c7\u00f6zme s\u00fcresi:     %.3f ms%n", totalDec / 100_000_000.0);
    }
    private static void test4_signatureVerification() {
    	System.out.println("📌 Test 4 – İmza Üretme & Doğrulama");

    	String msg = "Makbule'nin imzalanacak mesajı";
    	NtruSign ntru = new NtruSign(SignatureParameters.TEST157);
    	SignatureKeyPair kp = ntru.generateKeyPair();

    	byte[] sig = ntru.sign(msg.getBytes(), kp);
    	boolean valid = ntru.verify(msg.getBytes(), sig, kp.getPublic());

    	System.out.println("Mesaj: " + msg);
    	System.out.println("İmza geçerli mi? " + valid);
     }


    private static void test5_wrongKeyVerification() {
        System.out.println("\ud83d\udccc Test 5 \u2013 Yanl\u0131\u015f Anahtarla Do\u011frulama");
        String msg = "Makbule'nin mesaj\u0131";
        NtruSign ntru = new NtruSign(SignatureParameters.TEST157);
        SignatureKeyPair kp1 = ntru.generateKeyPair();
        SignatureKeyPair kp2 = ntru.generateKeyPair();
        byte[] sig = ntru.sign(msg.getBytes(), kp1);
        boolean valid = ntru.verify(msg.getBytes(), sig, kp2.getPublic());
        System.out.println("\u0130mza do\u011fru anahtarla m\u0131 do\u011fruland\u0131?: " + valid);
    }

    private static void test6_messageManipulation() {
        System.out.println("\ud83d\udccc Test 6 \u2013 Mesaj Manip\u00fclasyonu Testi");
        String msg = "Makbule'nin gizli mesaj\u0131";
        NtruSign ntru = new NtruSign(SignatureParameters.TEST157);
        SignatureKeyPair kp = ntru.generateKeyPair();
        byte[] sig = ntru.sign(msg.getBytes(), kp);
        String tamperedMsg = msg + "!!!";
        boolean valid = ntru.verify(tamperedMsg.getBytes(), sig, kp.getPublic());
        System.out.println("Mesaj de\u011fi\u015ftirildi: " + tamperedMsg);
        System.out.println("\u0130mza hala ge\u00e7erli mi?: " + valid);
    }

    private static void test7_signatureParameterComparison() {
        System.out.println("\ud83d\udccc Test 7 \u2013 Parametre Seti ile \u0130mza Kar\u015f\u0131la\u015ft\u0131rmas\u0131");
        String msg = "Parametre testi";
        NtruSign ntru = new NtruSign(SignatureParameters.TEST157);
        SignatureKeyPair kp = ntru.generateKeyPair();
        byte[] sig = ntru.sign(msg.getBytes(), kp);
        boolean valid = ntru.verify(msg.getBytes(), sig, kp.getPublic());
        System.out.println("\u0130mza do\u011fruland\u0131 m\u0131?: " + valid);
    }

    private static void test10_signatureRandomness() {
        System.out.println("\ud83d\udccc Test 10 \u2013 Ayn\u0131 Mesaj, Farkl\u0131 \u0130mzalar?");
        String msg = "Rastgele \u0130mza";
        NtruSign ntru = new NtruSign(SignatureParameters.TEST157);
        SignatureKeyPair kp = ntru.generateKeyPair();
        byte[] sig1 = ntru.sign(msg.getBytes(), kp);
        byte[] sig2 = ntru.sign(msg.getBytes(), kp);
        System.out.println("\u0130mzalar ayn\u0131 m\u0131?: " + Arrays.equals(sig1, sig2));
    }

    private static void test11_fakeMessageVerification() {
        System.out.println("\ud83d\udccc Test 11 \u2013 Sahte Mesaj Do\u011frulama");
        String msg = "Ger\u00e7ek mesaj";
        String fakeMsg = "Sahte mesaj";
        NtruSign ntru = new NtruSign(SignatureParameters.TEST157);
        SignatureKeyPair kp = ntru.generateKeyPair();
        byte[] sig = ntru.sign(msg.getBytes(), kp);
        boolean valid = ntru.verify(fakeMsg.getBytes(), sig, kp.getPublic());
        System.out.println("Sahte mesajla do\u011frulama sonucu: " + valid);
    }
}