package com.example.hellojni;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import android.text.TextUtils;
import android.util.Log;

public class ExecCmd {

    private static final boolean DEBUG = true;
    private static final String TAG = ExecCmd.class.getSimpleName();

    public static boolean ExecCmdByRoot() {
        boolean success = false;
        Process process = null;

        if (DEBUG) {
            Log.i(TAG, "ExecCmdByRoot");
        }
        // 启动su进程
        try {
            process = Runtime.getRuntime().exec("/system/bin/sh", null, new File("/system/bin")); // android中使用
            // proc = Runtime.getRuntime().exec("/bin/bash", null, new
            // File("/bin")); //Linux中使用
            // 至于windows，由于没有bash，和sh 所以这种方式可能行不通
        } catch (IOException e) {
            e.printStackTrace();
            Log.i(TAG, "exec process error " + e.getMessage());
            return false;
        }

        if (process != null) {
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            PrintWriter out =
                    new PrintWriter(new BufferedWriter(new OutputStreamWriter(process.getOutputStream())), true);
            out.println("cd /data/data/com.example.hellojni");
            out.println("pwd");
            // out.println("ls -l");
            out.println("su");
            out.println("chmod 777 inject");
            out.println("chmod 777 libhello.so");
            out.println("./inject");
            out.println("exit");
            try {
                String line;
                while ((line = in.readLine()) != null) {
                    System.out.println(line);
                    Log.i(TAG, line);
                }
                process.waitFor(); // 上面读这个流食阻塞的，所以waitfor 没太大必要性
                in.close();
                out.close();
                process.destroy();
            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }
        }
        return success;
    }

    public static boolean ExecCmdCommon(final String cmd) {
        boolean success = false;
        Process process = null;

        InputStream is = null;
        InputStream es = null;

        try {
            if (DEBUG) {
                Log.i(TAG, "exec su cmd");
            }
            // 启动su进程
            process = Runtime.getRuntime().exec(cmd);
            is = process.getInputStream();
            int exitValue = process.waitFor();

            if (DEBUG) {
                Log.i(TAG, "exec " + cmd + ", exitValue = " + exitValue);
            }

            if (exitValue == 0) {
                String result = readStringFromStream(is);
                if (!TextUtils.isEmpty(result) && result.toLowerCase().contains("success")) {
                    success = true;
                } else {
                    es = process.getErrorStream();
                    String error = readStringFromStream(es);
                    Log.i(TAG, "Exec " + cmd + " Erro : " + error);
                }
            }
        } catch (Exception e) {

        } finally {
            closeSilently(is);
            closeSilently(es);
            if (process != null) {
                try {
                    process.destroy();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        return success;
    }

    /**
     * 通过文件读取String
     * 
     * @param path
     * @return String
     */
    public static String readStringFromStream(InputStream inputStream) {
        String s = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (inputStream == null) {
            return null;
        }
        try {
            byte[] buff = new byte[1024];
            int readed = -1;
            while ((readed = inputStream.read(buff)) != -1) {
                baos.write(buff, 0, readed);
            }
            byte[] result = baos.toByteArray();
            if (result == null) {
                return null;
            }
            s = new String(result, "utf-8");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                baos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return s;
    }

    public static void closeSilently(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception e) {
                // Do nothing
            }
        }
    }
}
