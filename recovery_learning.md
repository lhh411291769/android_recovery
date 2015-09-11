updater流程梳理
===============

概述
----

    android在做ota升级时会从主系统进入recovery系统,recovery系统负责真正的系统
升级操作，包括一些分区/apk/和一些个库的升级.而在recvoery系统中做升级动作最终是
由updater完成的.
    updater程序中通解析update-script脚本命令完成升级的具体动作.

代码流程
--------

1. recovery升级代码最终都会调用到install_package
    * install_package函数

    对应文件: bootable/recovery/install.cpp

    ```C
    // 函数中调用了really_install_package,开始升级相应动作
    int install_package(const char* path, int* wipe_cache, const char* install_file,
                bool needs_mount)
    {
        ...

        int result;
        if (setup_install_mounts() != 0) {
            LOGE("failed to set up expected mounts for install; aborting\n");
            result = INSTALL_ERROR;
        } else {
            result = really_install_package(path, wipe_cache, needs_mount); //__主要动作__
        }

        ...

        return result;
    }
    ```

    * really_install_package函数

    对应文件: bootable/recovery/install.cpp

    ```C
    // 函数做升级前的检验，然后打开升级包交给try_update_binary升级
    static int
    really_install_package(const char *path, int* wipe_cache, bool needs_mount)
    {
        ...
        if (path && needs_mount) {
        if (path[0] == '@') {
            if (ensure_path_mounted(path+1) != 0) {
                LOGE("Can't mount %s\n", path);
                return INSTALL_CORRUPT;
            }
        } else {
            if (ensure_path_mounted(path) != 0) {
                LOGE("Can't mount %s\n", path);
                return INSTALL_CORRUPT;
            }
        }

        // 校验升级包签名
        MemMapping map;
        if (sysMapFile(path, &map) != 0) {
            LOGE("failed to map file\n");
            reset_mark_block();
            return INSTALL_CORRUPT;
        }

        int numKeys;

        // PUBLIC_KEYS_FILE = "/res/keys"
        Certificate* loadedKeys = load_keys(PUBLIC_KEYS_FILE, &numKeys);
        if (loadedKeys == NULL) {
            LOGE("Failed to load keys\n");
            reset_mark_block();
            return INSTALL_NO_KEY;
        }
        LOGI("%d key(s) loaded from %s\n", numKeys, PUBLIC_KEYS_FILE);

        LOGI("Verifying update package...\n");
        int err;
        err = verify_file(map.addr, map.length, loadedKeys, numKeys);
        free(loadedKeys);
        LOGI("verify_file returned %d\n", err);
        if (err != VERIFY_SUCCESS) {
            LOGE("signature verification failed\n");
            reset_mark_block();
            sysReleaseMap(&map);
            return INSTALL_SIGNATURE_ERROR;
        }

        /* Try to open the package.
         */
        ZipArchive zip;
        err = mzOpenZipArchive(map.addr, map.length, &zip);
        if (err != 0) {
            LOGE("Can't open %s\n(%s)\n", path, err != -1 ? strerror(err) : "bad");

        /* Verify and install the contents of the package.
         */
        ui->Print("Installing update...\n");
        ui->SetEnableReboot(false);
        int result = try_update_binary(path, &zip, wipe_cache); //__重要调用__
        ui->SetEnableReboot(true);
        ui->Print("\n");

        sysReleaseMap(&map);

        return result;
    }
    ```

    * try_update_binary函数


    ```C
    // 函数中fork一个子进程执行updater，自己接收updater
    static int
    try_update_binary(const char *path, ZipArchive *zip, int* wipe_cache) {

        // 从升级包中获取updater
        const ZipEntry* binary_entry =
                mzFindZipEntry(zip, ASSUMED_UPDATE_BINARY_NAME);
        if (binary_entry == NULL) {
            mzCloseZipArchive(zip);
            return INSTALL_CORRUPT;
        }

        const char* binary = "/tmp/update_binary";
        unlink(binary);
        int fd = creat(binary, 0755);
        if (fd < 0) {
            mzCloseZipArchive(zip);
            LOGE("Can't make %s\n", binary);
            return INSTALL_ERROR;
        }
        bool ok = mzExtractZipEntryToFile(zip, binary_entry, fd);
        close(fd);
        mzCloseZipArchive(zip);

        if (!ok) {
            LOGE("Can't copy %s\n", ASSUMED_UPDATE_BINARY_NAME);
            return INSTALL_ERROR;
        }

        // 创建通信管道
        int pipefd[2];
        pipe(pipefd);

        const char** args = (const char**)malloc(sizeof(char*) * 5);
        args[0] = binary;
        args[1] = EXPAND(RECOVERY_API_VERSION);   // defined in Android.mk
        char* temp = (char*)malloc(10);
        sprintf(temp, "%d", pipefd[1]);
        args[2] = temp;
        args[3] = (char*)path;
        args[4] = NULL;

        // 创建子进程运行updater
        pid_t pid = fork();
        if (pid == 0) {
            umask(022);
            close(pipefd[0]);
            execv(binary, (char* const*)args);
            fprintf(stdout, "E:Can't run %s (%s)\n", binary, strerror(errno));
            _exit(-1);
        }
        close(pipefd[1]);

        *wipe_cache = 0;

        // 父进程解析来自updater的控制消息，相应完成显示updater升级进度，及打
        // 印信息输出等动作
        char buffer[1024];
        FILE* from_child = fdopen(pipefd[0], "r");
        while (fgets(buffer, sizeof(buffer), from_child) != NULL) {
            char* command = strtok(buffer, " \n");
            if (command == NULL) {
                continue;
            } else if (strcmp(command, "progress") == 0) {
                char* fraction_s = strtok(NULL, " \n");
                char* seconds_s = strtok(NULL, " \n");

                float fraction = strtof(fraction_s, NULL);
                int seconds = strtol(seconds_s, NULL, 10);

                ui->ShowProgress(fraction * (1-VERIFICATION_PROGRESS_FRACTION), seconds);
            } else if (strcmp(command, "set_progress") == 0) {
                char* fraction_s = strtok(NULL, " \n");
                float fraction = strtof(fraction_s, NULL);
                ui->SetProgress(fraction);
            } else if (strcmp(command, "ui_print") == 0) {
                char* str = strtok(NULL, "\n");
                if (str) {
                    ui->Print("%s", str);
                } else {
                    ui->Print("\n");
                }
                fflush(stdout);
            } else if (strcmp(command, "wipe_cache") == 0) {
                *wipe_cache = 1;

            } else if (strcmp(command, "special_factory_reset") == 0) {
                *wipe_cache = 2;
            } else if (strcmp(command, "clear_display") == 0) {
                ui->SetBackground(RecoveryUI::NONE);
            } else if (strcmp(command, "enable_reboot") == 0) {
                // packages can explicitly request that they want the user
                // to be able to reboot during installation (useful for
                // debugging packages that don't exit).
                ui->SetEnableReboot(true);
            } else {
                LOGE("unknown command [%s]\n", command);
            }
        }
        fclose(from_child);

        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            LOGE("Error in %s\n(Status %d)\n", path, WEXITSTATUS(status));
            return INSTALL_ERROR;
        }

        return INSTALL_SUCCESS;
    }
    ```
