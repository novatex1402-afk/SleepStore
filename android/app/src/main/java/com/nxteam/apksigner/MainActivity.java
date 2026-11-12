package com.nxteam.apksigner;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    private static final int REQ_PICK_APK = 1;
    private static final int REQ_SAVE_APK = 2;
    private static final int REQ_PICK_KEYSTORE = 3;
    private static final int REQ_EXPORT_KEY = 4;
    private static final String APK_MIME = "application/vnd.android.package-archive";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());

    private KeyManager keys;
    private TextView txtApk, txtKey, txtLog;
    private Button btnSign, btnInstall;
    private ProgressBar progress;

    private Uri inputUri;
    private String inputName = "app.apk";
    private File signedFile;
    private Uri savedUri;
    private String pendingExportPassword;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        txtApk = findViewById(R.id.txtApk);
        txtKey = findViewById(R.id.txtKey);
        txtLog = findViewById(R.id.txtLog);
        btnSign = findViewById(R.id.btnSign);
        btnInstall = findViewById(R.id.btnInstall);
        progress = findViewById(R.id.progress);

        findViewById(R.id.btnPick).setOnClickListener(v -> pickApk());
        findViewById(R.id.btnImport).setOnClickListener(v -> pickKeystore());
        findViewById(R.id.btnExport).setOnClickListener(v -> askExportPassword());
        findViewById(R.id.btnNewKey).setOnClickListener(v -> confirmNewKey());
        btnSign.setOnClickListener(v -> sign());
        btnInstall.setOnClickListener(v -> install());

        keys = new KeyManager(this);
        txtKey.setText("Anahtar hazırlanıyor…");
        runBg(() -> {
            keys.loadOrCreate();
            return null;
        }, r -> refreshKey());

        handleIncoming(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIncoming(intent);
    }

    /** Dosya yöneticisinden "Birlikte aç" / "Paylaş" ile gelen APK. */
    private void handleIncoming(Intent intent) {
        if (intent == null) return;
        Uri uri = null;
        if (Intent.ACTION_VIEW.equals(intent.getAction())) {
            uri = intent.getData();
        } else if (Intent.ACTION_SEND.equals(intent.getAction())) {
            uri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
        }
        if (uri != null) setInput(uri);
    }

    // ---------------------------------------------------------------- APK seçimi

    private void pickApk() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{APK_MIME, "application/octet-stream", "application/zip"});
        startActivityForResult(i, REQ_PICK_APK);
    }

    private void setInput(Uri uri) {
        inputUri = uri;
        inputName = queryName(uri, "app.apk");
        txtApk.setText("Seçilen: " + inputName);
        btnSign.setEnabled(true);
        btnInstall.setVisibility(View.GONE);
        txtLog.setText("");
    }

    // ---------------------------------------------------------------- İmzalama

    private void sign() {
        if (inputUri == null) return;
        if (keys.getPrivateKey() == null) {
            toast("Anahtar henüz hazır değil");
            return;
        }
        setBusy(true);
        txtLog.setText("İmzalanıyor…\n");
        final Uri src = inputUri;
        runBg(() -> {
            File in = new File(getCacheDir(), "input.apk");
            File out = new File(getCacheDir(), "signed.apk");
            copy(getContentResolver().openInputStream(src), new FileOutputStream(in));

            ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                    "CERT", keys.getPrivateKey(),
                    Collections.singletonList(keys.getCertificate())).build();

            new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(in)
                    .setOutputApk(out)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setCreatedBy("APK Signer (apksig)")
                    .build()
                    .sign();

            // Doğrula
            ApkVerifier.Result res = new ApkVerifier.Builder(out).build().verify();
            StringBuilder sb = new StringBuilder();
            sb.append(res.isVerified() ? "✔ İmza doğrulandı\n" : "✘ Doğrulama BAŞARISIZ\n");
            sb.append("v1 (JAR, yalnızca Android 7 öncesi gerekir): ").append(yesNo(res.isVerifiedUsingV1Scheme())).append('\n');
            sb.append("v2: ").append(yesNo(res.isVerifiedUsingV2Scheme())).append('\n');
            sb.append("v3: ").append(yesNo(res.isVerifiedUsingV3Scheme())).append('\n');
            sb.append("Boyut: ").append(out.length() / 1024).append(" KB\n");
            for (ApkVerifier.IssueWithParams e : res.getErrors()) sb.append("HATA: ").append(e).append('\n');
            in.delete();
            if (!res.isVerified()) throw new Exception(sb.toString());
            signedFile = out;
            return sb.toString();
        }, log -> {
            setBusy(false);
            txtLog.setText(log + "\nŞimdi nereye kaydedileceğini seçin…");
            askSaveLocation();
        });
    }

    private void askSaveLocation() {
        String base = inputName.toLowerCase().endsWith(".apk")
                ? inputName.substring(0, inputName.length() - 4) : inputName;
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(APK_MIME);
        i.putExtra(Intent.EXTRA_TITLE, base + "-signed.apk");
        startActivityForResult(i, REQ_SAVE_APK);
    }

    private void saveSigned(Uri dest) {
        setBusy(true);
        runBg(() -> {
            copy(new FileInputStream(signedFile), getContentResolver().openOutputStream(dest, "wt"));
            return null;
        }, r -> {
            setBusy(false);
            savedUri = dest;
            txtLog.append("\n\n✔ Kaydedildi: " + queryName(dest, "signed.apk"));
            btnInstall.setVisibility(View.VISIBLE);
            toast("İmzalı APK kaydedildi");
        });
    }

    private void install() {
        if (savedUri == null) return;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                && !getPackageManager().canRequestPackageInstalls()) {
            toast("Lütfen bu uygulamaya 'Bilinmeyen uygulamaları yükle' izni verin");
            startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:" + getPackageName())));
            return;
        }
        Intent i = new Intent(Intent.ACTION_VIEW);
        i.setDataAndType(savedUri, APK_MIME);
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            startActivity(i);
        } catch (Exception e) {
            toast("Yükleyici açılamadı: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------- Anahtar işlemleri

    private void refreshKey() {
        txtKey.setText(keys.describe());
    }

    private void confirmNewKey() {
        EditText name = new EditText(this);
        name.setHint("Ad (ör. Adınız veya şirketiniz)");
        name.setText("APK Signer");
        new AlertDialog.Builder(this)
                .setTitle("Yeni anahtar oluştur")
                .setMessage("Mevcut anahtar SİLİNİR. Eski anahtarla imzaladığınız uygulamaları artık "
                        + "güncelleyemezsiniz. Önce yedek almanız önerilir.")
                .setView(wrap(name))
                .setPositiveButton("Oluştur", (d, w) -> {
                    String cn = name.getText().toString().trim();
                    txtKey.setText("Yeni anahtar üretiliyor…");
                    runBg(() -> {
                        keys.generate(cn.isEmpty() ? "APK Signer" : cn);
                        return null;
                    }, r -> {
                        refreshKey();
                        toast("Yeni anahtar oluşturuldu");
                    });
                })
                .setNegativeButton("İptal", null)
                .show();
    }

    private void pickKeystore() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i, REQ_PICK_KEYSTORE);
    }

    private void askImportDetails(Uri uri) {
        EditText storePw = new EditText(this);
        storePw.setHint("Depo şifresi");
        storePw.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        EditText alias = new EditText(this);
        alias.setHint("Takma ad / alias (boş = ilk anahtar)");
        EditText keyPw = new EditText(this);
        keyPw.setHint("Anahtar şifresi (boş = depo şifresi)");
        keyPw.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);

        new AlertDialog.Builder(this)
                .setTitle("Anahtar içe aktar")
                .setMessage("Desteklenen: .p12 / .pfx (PKCS#12) ve .bks\n"
                        + "Not: .jks dosyasını bilgisayarda şu komutla çevirin:\n"
                        + "keytool -importkeystore -srckeystore a.jks -destkeystore a.p12 -deststoretype PKCS12")
                .setView(wrap(storePw, alias, keyPw))
                .setPositiveButton("İçe aktar", (d, w) -> runBg(() -> {
                    byte[] data = readAll(getContentResolver().openInputStream(uri));
                    keys.importKeystore(data, storePw.getText().toString(),
                            alias.getText().toString().trim(), keyPw.getText().toString());
                    return null;
                }, r -> {
                    refreshKey();
                    toast("Anahtar içe aktarıldı");
                }))
                .setNegativeButton("İptal", null)
                .show();
    }

    private void askExportPassword() {
        if (keys.getPrivateKey() == null) return;
        EditText pw = new EditText(this);
        pw.setHint("Yedek için şifre belirleyin");
        pw.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        new AlertDialog.Builder(this)
                .setTitle("Anahtarı yedekle")
                .setMessage("Bu dosyayı kaybederseniz imzaladığınız uygulamaları güncelleyemezsiniz. "
                        + "Güvenli bir yerde saklayın ve kimseyle paylaşmayın.")
                .setView(wrap(pw))
                .setPositiveButton("Devam", (d, w) -> {
                    String p = pw.getText().toString();
                    if (p.length() < 4) {
                        toast("Şifre en az 4 karakter olmalı");
                        return;
                    }
                    pendingExportPassword = p;
                    Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                    i.addCategory(Intent.CATEGORY_OPENABLE);
                    i.setType("application/x-pkcs12");
                    i.putExtra(Intent.EXTRA_TITLE, "apk-signer-key.p12");
                    startActivityForResult(i, REQ_EXPORT_KEY);
                })
                .setNegativeButton("İptal", null)
                .show();
    }

    // ---------------------------------------------------------------- Sonuçlar

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            if (requestCode == REQ_SAVE_APK && signedFile != null) {
                txtLog.append("\nKaydetme iptal edildi. Tekrar 'İMZALA VE KAYDET'e basabilirsiniz.");
            }
            return;
        }
        Uri uri = data.getData();
        switch (requestCode) {
            case REQ_PICK_APK:
                setInput(uri);
                break;
            case REQ_SAVE_APK:
                saveSigned(uri);
                break;
            case REQ_PICK_KEYSTORE:
                askImportDetails(uri);
                break;
            case REQ_EXPORT_KEY:
                final String pw = pendingExportPassword;
                pendingExportPassword = null;
                runBg(() -> {
                    try (OutputStream out = getContentResolver().openOutputStream(uri, "wt")) {
                        keys.export(out, pw);
                    }
                    return null;
                }, r -> toast("Anahtar yedeklendi"));
                break;
        }
    }

    // ---------------------------------------------------------------- Yardımcılar

    interface Task<T> { T run() throws Exception; }

    interface Done<T> { void done(T result); }

    private <T> void runBg(Task<T> task, Done<T> done) {
        executor.execute(() -> {
            try {
                T r = task.run();
                main.post(() -> done.done(r));
            } catch (Throwable e) {
                main.post(() -> {
                    setBusy(false);
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    txtLog.append("\n✘ Hata: " + msg);
                    new AlertDialog.Builder(this).setTitle("Hata").setMessage(msg)
                            .setPositiveButton("Tamam", null).show();
                    if (keys.getCertificate() != null) refreshKey();
                });
            }
        });
    }

    private void setBusy(boolean busy) {
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        btnSign.setEnabled(!busy && inputUri != null);
    }

    private LinearLayout wrap(View... views) {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        int p = (int) (20 * getResources().getDisplayMetrics().density);
        l.setPadding(p, p / 2, p, 0);
        for (View v : views) l.addView(v);
        return l;
    }

    private String queryName(Uri uri, String fallback) {
        try (Cursor c = getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                String n = c.getString(0);
                if (n != null && !n.isEmpty()) return n;
            }
        } catch (Exception ignored) {
        }
        String last = uri.getLastPathSegment();
        return last != null ? last : fallback;
    }

    private static void copy(InputStream in, OutputStream out) throws Exception {
        if (in == null || out == null) throw new Exception("Dosya açılamadı");
        try (InputStream i = in; OutputStream o = out) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = i.read(buf)) > 0) o.write(buf, 0, n);
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        copy(in, bos);
        return bos.toByteArray();
    }

    private static String yesNo(boolean b) { return b ? "evet" : "hayır"; }

    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_LONG).show(); }
}
