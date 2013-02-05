
package com.android.certinstaller;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.security.Credentials;
import android.security.CryptOracle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import java.io.File;

public class KeyFileList extends CertFileList {
    private static final String EXTENSION_KEY = ".key";
    private static final String EXTENSION_PEM = ".pem";
    private static final String keyChainPackage = "com.android.keychain";
    private static final int MAX_FILE_SIZE = 1000000;
    private static final String TAG = "KeyFileList";
    private CredentialHelper mCredentials;

    private final AsyncTask<String, Void, Boolean> mExtractionTask = new AsyncTask<String, Void, Boolean>() {
        protected void onPostExecute(Boolean result) {
            onInstallationDone(result);
            if (result) {
                Intent i = mCredentials.createSystemInstallIntent();
                setResult(RESULT_OK, new Intent().putExtras(i.getExtras()));
                finish();
                return;
            }
            toastError(R.string.cert_not_saved);
            finish();
        }

        @Override
        protected Boolean doInBackground(String... params) {
            mCredentials.setName(params[0]);
            return mCredentials.extractPkcs12(params[1]);
        };
    };

    private void install(String fileName, byte[] value) {
        if (fileName.toLowerCase().endsWith(Credentials.EXTENSION_P12)
                || fileName.toLowerCase().endsWith(Credentials.EXTENSION_PFX)) {
            mCredentials = new CredentialHelper();
            mCredentials.putPkcs12Data(value);

            showPasswordNameDialog(fileName);
        } else if (fileName.endsWith(EXTENSION_KEY)) {
            Intent resultData = new Intent();
            resultData.putExtra(CryptOracle.EXTRA_SYMKEY, value);
            onInstallationDone(true);
            setResult(RESULT_OK, resultData);
            finish();
        } else {
            onInstallationDone(false);
            Toast.makeText(this, "not yet implemented", Toast.LENGTH_SHORT).show();
        }
    }

    private void showPasswordNameDialog(String fileName) {
        final View view = getLayoutInflater().inflate(R.layout.password_name_dialog, null);
        
        final ViewHelper viewHelper = new ViewHelper();
        viewHelper.setView(view);
        
        AlertDialog.Builder alert = new AlertDialog.Builder(this);
        alert.setView(view);
        alert.setTitle(getString(R.string.pkcs12_file_password_dialog_title, fileName));
        alert.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
            
            @Override
            public void onClick(DialogInterface dialog, int which) {
            }
        });
        
        
        // workaround for auto-dismissal, I'm too tired to write a proper dialog
        final AlertDialog d = alert.create();
        d.setOnShowListener(new DialogInterface.OnShowListener() {

            @Override
            public void onShow(DialogInterface dialog) {

                Button b = d.getButton(AlertDialog.BUTTON_POSITIVE);
                b.setOnClickListener(new View.OnClickListener() {

                    @Override
                    public void onClick(View view) {
                        String name = viewHelper.getText(R.id.credential_name);
                        String password = viewHelper.getText(R.id.credential_password);
                        
                        if (TextUtils.isEmpty(name)) {
                            viewHelper.showError(R.string.name_empty_error);
                        } else if (TextUtils.isEmpty(password)) {
                            viewHelper.showError(R.string.password_empty_error);
                        } else {
                            d.dismiss();
                            
                            mExtractionTask.execute(name, password);
                        }
                    }
                });
            }
        });
        d.show();
    }

    @Override
    protected void installFromFile(File file) {
        Log.d(TAG, "install key from " + file);

        String fileName = file.getName();
        if (file.exists()) {
            if (file.length() < MAX_FILE_SIZE) {
                byte[] data = Util.readFile(file);
                if (data == null) {
                    toastError(CERT_READ_ERROR);
                    onError(CERT_READ_ERROR);
                    return;
                }
                mCertFile = file;
                install(fileName, data);
            } else {
                Log.w(TAG, "key file is too large: " + file.length());
                toastError(CERT_TOO_LARGE_ERROR);
                onError(CERT_TOO_LARGE_ERROR);
            }
        } else {
            Log.w(TAG, "key file does not exist");
            toastError(CERT_FILE_MISSING_ERROR);
            onError(CERT_FILE_MISSING_ERROR);
        }
    }

    @Override
    protected boolean isFileAcceptable(String path) {
        return (path.endsWith(EXTENSION_PEM) ||
                path.endsWith(Credentials.EXTENSION_P12)
                || path.endsWith(Credentials.EXTENSION_PFX)
                || path.endsWith(EXTENSION_KEY));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String callerPackage = getCallingPackage();
        if (!keyChainPackage.equals(callerPackage)) {
            Log.e(TAG, "not allowed to answer to calling package " + callerPackage);
            setResult(RESULT_CANCELED);
            finish();
        }
    }

    private void toastError(int msgId) {
        Toast.makeText(this, msgId, Toast.LENGTH_LONG).show();
    }
}
