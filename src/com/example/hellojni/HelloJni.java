/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.hellojni;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;


public class HelloJni extends Activity
{
    private static final String TAG = HelloJni.class.getSimpleName();
    private String exe_path = "/data/data/com.example.hellojni/inject";
    private String exe_path_so = "/data/data/com.example.hellojni/libhello.so";

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        /* Create a TextView and set its content.
         * the text is retrieved by calling a native
         * function.
         */
        requestRootAccess();
        TextView  tv = new TextView(this);
        // tv.setText(stringFromJNI());
        // tv.setText(fromJNI());
        setContentView(tv);
        runInjectByRoot();
    }

    private void requestRootAccess() {
        final boolean root = RootTool.requestRootAccess();
        Toast.makeText(this, root ? "Root Success!" : "Root Failed!!", Toast.LENGTH_LONG).show();
    }

    private void runInjectByRoot() {
        // this.getFilesDir().getPath();
        copyDataToSD("inject", exe_path);
        copyDataToSD("libhello.so", exe_path_so);
        ExecCmd.ExecCmdByRoot();
    }

    private void copyDataToSD(final String assetFileName, final String strOutFileName) {
        Log.i(TAG, "copyDataToSD assetFileName = " + assetFileName + " strOutFileName = " + strOutFileName);
        InputStream input = null;
        OutputStream out = null;
        try {
            File file = new File(strOutFileName);
            if (file.exists()) {
                return;
            }
            out = new FileOutputStream(file);
            input = this.getAssets().open(assetFileName);
            byte[] buffer = new byte[1024];
            int length = input.read(buffer);
            while (length > 0) {
                out.write(buffer, 0, length);
                length = input.read(buffer);
            }
            out.flush();
            Log.i(TAG, "copyDataToSD Finish");
        } catch (Exception e) {
            Log.i(TAG, "copyDataToSD exception " + e.getMessage());
        } finally {
            ExecCmd.closeSilently(out);
            ExecCmd.closeSilently(input);
        }
    }

    /* A native method that is implemented by the
     * 'hello-jni' native library, which is packaged
     * with this application.
     */
    public native String  stringFromJNI();

    /* This is another native method declaration that is *not*
     * implemented by 'hello-jni'. This is simply to show that
     * you can declare as many native methods in your Java code
     * as you want, their implementation is searched in the
     * currently loaded native libraries only the first time
     * you call them.
     *
     * Trying to call this function will result in a
     * java.lang.UnsatisfiedLinkError exception !
     */
    public native String  unimplementedStringFromJNI();

    /* this is used to load the 'hello-jni' library on application
     * startup. The library has already been unpacked into
     * /data/data/com.example.hellojni/lib/libhello-jni.so at
     * installation time by the package manager.
     */
    
    public native String fromJNI();
    static {
        System.loadLibrary("hello");
        // System.loadLibrary("inject");
    }
}
