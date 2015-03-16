package com.example.hellojni;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

import android.content.Context;
import android.util.Log;

public class RootTool {

    private static final boolean DEBUG = true;
    private static final String TAG = "RootTools";

    public static final int STATUS_UNKONW = -1;
    public static final int STATUS_NOT_ROOTED = 0;
    public static final int STATUS_ROOTED = 1;

    private static int sRootedStatus = STATUS_UNKONW;

    public static void init(final Context context) {
        // 检查设备ROOT状态
        checkDeviceRooted(context);
    }

    private static boolean findBinary(String binaryName) {
        boolean found = false;
        if (!found) {
            String[] places =
                    { "/sbin/", "/system/bin/", "/system/xbin/", "/data/local/xbin/", "/data/local/bin/",
                            "/system/sd/xbin/", "/system/bin/failsafe/", "/data/local/" };
            for (String where : places) {
                if (new File(where + binaryName).exists()) {
                    found = true;

                    break;
                }
            }
        }
        return found;
    }

    private static boolean isSuBinExist() {
        return findBinary("su");
    }

    private static boolean isBuildTestKey() {

        // get from build info
        String buildTags = android.os.Build.TAGS;
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true;
        }

        return false;
    }

    private static boolean isUserRooted() {
        // check if /system/app/Superuser.apk is present
        try {
            File file = new File("/system/app/Superuser.apk");
            if (file.exists()) {
                return true;
            }
        } catch (Throwable e1) {
            // ignore
        }
        return false;
    }

    private static boolean executeShellCommand(String command) {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(command);
            return true;
        } catch (Throwable e) {
            return false;
        } finally {
            if (process != null) {
                try {
                    process.destroy();
                } catch (Throwable e) {

                }
            }
        }
    }

    public static boolean checkDeviceRooted(Context context) {
        if (isUserRooted() || executeShellCommand("su") || findBinary("su")) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean requestRootAccess() {
        boolean success = false;
        Process process = null;

        OutputStream os = null;
        DataOutputStream dos = null;
        InputStream is = null;
        DataInputStream dis = null;

        try {
            if (DEBUG) {
                Log.i(TAG, "request root access");
            }

            // 启动su进程
            process = Runtime.getRuntime().exec("su");

            os = process.getOutputStream();
            is = process.getInputStream();
            if (os != null && is != null) {
                dos = new DataOutputStream(os);
                dis = new DataInputStream(is);

                // 获取用户信息
                dos.writeBytes("id\n");
                dos.flush();

                String result = dis.readLine();
                if (result != null && result.toLowerCase().contains("uid=0")) {
                    success = true;

                    if (DEBUG) {
                        Log.i(TAG, "request root access, success!");
                    }

                    dos.writeBytes("exit\n"); // 先退出su用户
                    os.flush();
                } else {
                    success = false;

                    if (DEBUG) {
                        Log.i(TAG, "request root access, failed!");
                    }
                }

                // 等待进程执行完成
                int exitValue = process.waitFor();

                if (DEBUG) {
                    Log.i(TAG, "request root access, exitValue=" + exitValue);
                }
            }
        } catch (Exception e) {
            // su不存在，或执行失败会抛出异常
            e.printStackTrace();
        } finally {
            if (dos != null) {
                try {
                    dos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            if (dis != null) {
                try {
                    dis.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
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
}
