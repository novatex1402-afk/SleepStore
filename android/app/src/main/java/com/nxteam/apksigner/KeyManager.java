package com.nxteam.apksigner;

import android.content.Context;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

/**
 * Uygulamanın kullandığı imza anahtarını yönetir.
 *
 * Anahtar, uygulamanın özel klasöründe PKCS#12 (.p12) dosyası olarak saklanır.
 * İlk açılışta ücretsiz, kendinden imzalı (self-signed) bir RSA-2048 sertifikası üretilir.
 * Android APK imzası için sertifika otoritesi (CA) gerekmez; kendinden imzalı sertifika
 * Google Play dahil her yerde geçerlidir.
 */
public final class KeyManager {

    private static final String FILE_NAME = "signing.p12";
    private static final String ALIAS = "key";
    // Dosya zaten uygulamanın özel klasöründe; bu şifre yalnızca dahili depolama içindir.
    private static final char[] INTERNAL_PASSWORD = "apksigner-internal".toCharArray();

    private final File file;
    private PrivateKey privateKey;
    private X509Certificate certificate;

    public KeyManager(Context context) {
        this.file = new File(context.getFilesDir(), FILE_NAME);
    }

    public PrivateKey getPrivateKey() { return privateKey; }

    public X509Certificate getCertificate() { return certificate; }

    /** Kayıtlı anahtarı yükler; yoksa yeni bir tane üretir. */
    public synchronized void loadOrCreate() throws Exception {
        if (file.exists()) {
            try (InputStream in = new FileInputStream(file)) {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(in, INTERNAL_PASSWORD);
                privateKey = (PrivateKey) ks.getKey(ALIAS, INTERNAL_PASSWORD);
                certificate = (X509Certificate) ks.getCertificate(ALIAS);
                if (privateKey != null && certificate != null) return;
            }
        }
        generate("APK Signer");
    }

    /** Yeni, ücretsiz, kendinden imzalı RSA-2048 anahtar + 30 yıllık sertifika üretir. */
    public synchronized void generate(String commonName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=" + commonName.replace(",", " ") + ", O=APK Signer, C=TR");
        Date notBefore = new Date(System.currentTimeMillis() - 24L * 3600 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + 30L * 365 * 24 * 3600 * 1000);
        BigInteger serial = new BigInteger(63, new SecureRandom());

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);

        save(kp.getPrivate(), cert);
    }

    /**
     * Kullanıcının kendi anahtar deposunu (.p12 / .pfx / .bks) içe aktarır.
     * @param alias boş bırakılırsa ilk anahtar kullanılır
     * @param keyPassword boş bırakılırsa depo şifresi kullanılır
     */
    public synchronized void importKeystore(byte[] data, String storePassword,
                                            String alias, String keyPassword) throws Exception {
        char[] sp = storePassword.toCharArray();
        char[] kpw = (keyPassword == null || keyPassword.isEmpty()) ? sp : keyPassword.toCharArray();

        KeyStore ks = null;
        Exception last = null;
        for (String type : new String[]{"PKCS12", "BKS"}) {
            try {
                KeyStore k = KeyStore.getInstance(type);
                k.load(new java.io.ByteArrayInputStream(data), sp);
                ks = k;
                break;
            } catch (Exception e) {
                last = e;
            }
        }
        if (ks == null) {
            throw new Exception("Anahtar deposu açılamadı (şifre yanlış olabilir ya da format desteklenmiyor. "
                    + "JKS dosyalarını önce bilgisayarda .p12'ye çevirin). Ayrıntı: "
                    + (last != null ? last.getMessage() : "?"));
        }

        String useAlias = alias;
        if (useAlias == null || useAlias.isEmpty()) {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                if (ks.isKeyEntry(a)) { useAlias = a; break; }
            }
        }
        if (useAlias == null || !ks.isKeyEntry(useAlias)) {
            throw new Exception("Depoda özel anahtar bulunamadı" + (alias != null && !alias.isEmpty() ? " (takma ad: " + alias + ")" : ""));
        }

        PrivateKey pk = (PrivateKey) ks.getKey(useAlias, kpw);
        Certificate c = ks.getCertificate(useAlias);
        if (pk == null || !(c instanceof X509Certificate)) {
            throw new Exception("Anahtar veya sertifika okunamadı (anahtar şifresi yanlış olabilir)");
        }
        save(pk, (X509Certificate) c);
    }

    /** Mevcut anahtarı verilen şifreyle .p12 olarak dışa aktarır (yedek). */
    public synchronized void export(OutputStream out, String password) throws Exception {
        char[] pw = password.toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(ALIAS, privateKey, pw, new Certificate[]{certificate});
        ks.store(out, pw);
    }

    private void save(PrivateKey pk, X509Certificate cert) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(ALIAS, pk, INTERNAL_PASSWORD, new Certificate[]{cert});
        File tmp = new File(file.getPath() + ".tmp");
        try (OutputStream out = new FileOutputStream(tmp)) {
            ks.store(out, INTERNAL_PASSWORD);
        }
        if (!tmp.renameTo(file)) throw new Exception("Anahtar kaydedilemedi");
        privateKey = pk;
        certificate = cert;
    }

    /** Ekranda göstermek için sertifika özeti. */
    public String describe() {
        if (certificate == null) return "Anahtar yok";
        SimpleDateFormat df = new SimpleDateFormat("dd.MM.yyyy", Locale.getDefault());
        return "Sahip: " + certificate.getSubjectX500Principal().getName() + "\n"
                + "Algoritma: " + privateKey.getAlgorithm() + "\n"
                + "Geçerlilik: " + df.format(certificate.getNotAfter()) + " tarihine kadar\n"
                + "SHA-256: " + fingerprint(certificate);
    }

    static String fingerprint(X509Certificate cert) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < d.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02X", d[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "?";
        }
    }
}
