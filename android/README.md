# APK İmzalayıcı (Android)

Telefonda çalışan, tamamen **ücretsiz** APK imzalama uygulaması.

## Nasıl çalışır
1. **APK Seç** → imzalanacak APK'yı seçin (veya dosya yöneticisinde APK'ya "Birlikte aç → APK İmzalayıcı").
2. İlk açılışta uygulama sizin için **ücretsiz, kendinden imzalı** bir RSA-2048 anahtar üretir
   (30 yıl geçerli). İsterseniz kendi `.p12 / .pfx / .bks` anahtarınızı **içe aktarabilirsiniz**.
3. **İMZALA VE KAYDET** → v1 + v2 + v3 ile imzalar, doğrular, kaydedilecek yeri sorar.
4. **İmzalanan APK'yı Yükle** ile direkt kurabilirsiniz.

## Kullanılan ücretsiz araçlar
- [`apksig`](https://android.googlesource.com/platform/tools/apksig/) — Google'ın resmi, açık kaynak
  (Apache 2.0) kütüphanesi; Android SDK'daki `apksigner` aracının ta kendisi.
- [BouncyCastle](https://www.bouncycastle.org/) — sertifika üretimi (MIT lisansı).

Android APK imzası için para ödenen bir sertifikaya (CA) **gerek yoktur**; kendinden imzalı
sertifika Google Play dahil her yerde geçerlidir.

## Önemli
- **Anahtarınızı yedekleyin** ("Yedekle (.p12)"). Anahtarı kaybederseniz, onunla imzaladığınız
  uygulamaların güncellemesini yapamazsınız.
- Farklı anahtarla imzalanan bir APK, telefonda yüklü olan orijinal uygulamanın üzerine kurulamaz;
  önce eskisini kaldırmak gerekir.

## Derleme
GitHub → **Actions → Build Android (APK İmzalayıcı)** → son çalışmadaki `ApkImzalayici-apk`
dosyasını indirin. Yerelde: `cd android && ./gradlew assembleRelease`.
