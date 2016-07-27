package gensignature.android.com.gen_signature_android;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private static final String TAG = "MainActivity";
    private EditText etPackageName;
    private TextView tvSignature;

    private String md5 = "", sha1 = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        etPackageName = (EditText) findViewById(R.id.et_package_name);
        tvSignature = (TextView) findViewById(R.id.tv_signature);
        findViewById(R.id.btn_get_signature).setOnClickListener(this);
        findViewById(R.id.btn_copy_md5).setOnClickListener(this);

        findViewById(R.id.btn_copy_sha1).setOnClickListener(this);
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_get_signature:
                getSingInfo(etPackageName.getText().toString());
                getSign(etPackageName.getText().toString());
                break;
            case R.id.btn_copy_md5:
                copyFromText("md5", md5);
                break;
            case R.id.btn_copy_sha1:
                copyFromText("sha1", sha1);
                break;
        }
    }

    public void getSingInfo(String packageName) {
        PackageInfo packageInfo;
        try {
            packageInfo = getPackageManager().getPackageInfo(
                    packageName, PackageManager.GET_SIGNATURES);
            Signature[] signs = packageInfo.signatures;
            Signature sign = signs[0];
            parseSignature(sign.toByteArray());
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            tvSignature.setText("NameNotFoundException \nsigns is null");
        } catch (CertificateException e) {
            e.printStackTrace();
            tvSignature.setText("CertificateException \nsigns is null");
        }
    }

    public void parseSignature(byte[] signature) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory
                .getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory
                .generateCertificate(new ByteArrayInputStream(signature));
        String pubKey = cert.getPublicKey().toString();
        String signNumber = cert.getSerialNumber().toString();
        System.out.println(pubKey + "\n" + signNumber);
    }

    private void copyFromText(String label, String text) {
        // Gets a handle to the clipboard service.
        ClipboardManager mClipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        // Creates a new text clip to put on the clipboard
        ClipData clip = ClipData.newPlainText(label,
                text);
        // Set the clipboard's primary clip.
        mClipboard.setPrimaryClip(clip);
    }

    public void getSign(String packageName) {
        try {
            PackageInfo pi = getPackageManager().getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            Signature signatures = pi.signatures[0];
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(signatures.toByteArray());
            byte[] digest = md.digest();
            String res = toHexString(digest);

            StringBuilder builder = new StringBuilder();
            Log.e(TAG, "apk MD5 = " + res);
            md5 = res;
            builder.append("MD5 = ").append(res);
            MessageDigest md2 = MessageDigest.getInstance("SHA1");
            md2.update(signatures.toByteArray());
            byte[] digest2 = md.digest();
            String res2 = toHexString(digest2);
            Log.e(TAG, "apk SHA1 = " + res2);
            sha1 = res2;
            builder.append("\nSHA1 = ").append(res2);
            ByteArrayInputStream bais = new ByteArrayInputStream(signatures.toByteArray());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
            String sigAlgName = cert.getSigAlgName();
            String subjectDN = cert.getSubjectDN().toString();
            Log.e(TAG, "sigAlgName = " + sigAlgName);
            Log.e(TAG, "subjectDN = " + subjectDN);
            builder.append("\nsigAlgName = ").append(sigAlgName);
            builder.append("\nsubjectDN = ").append(subjectDN);
            bais.close();
            tvSignature.setText(builder.toString());
        } catch (Exception e) {
            e.printStackTrace();
            md5 = sha1 = "";
            tvSignature.setText(e.getMessage() + " \nsigns is null");
        }
    }

    /**
     * Converts a byte array to hex string
     *
     * @param block
     * @return
     */
    private String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len - 1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }

    private void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

}
