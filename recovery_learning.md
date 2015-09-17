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

    对应文件: bootable/recovery/install.cpp

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

        // updater程序文件
        const char* binary = "/tmp/update_binary";
        unlink(binary);
        int fd = creat(binary, 0755);
        if (fd < 0) {
            mzCloseZipArchive(zip);
            LOGE("Can't make %s\n", binary);
            return INSTALL_ERROR;
        }

        // 从zip包中解压出updater程序，写到上述文件中
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

    ota_from_target_files 脚本在做升级包的时候将updater程序放在了META-INF/com/google/android/
目录下，对应的名字是update-binary，这里通过这个名字在升级包中找到程序并将其解压到/tmp/目录
下的update_binary文件中.
    得到了升级程序之后，创建子进程运行这个程序，主进程解析来在updater发过来的消息，据此完成
相应的操作.

* updater程序的main函数

    对应文件: bootable/recovery/updater/updater.c

    ```C
    int main(int argc, char** argv) {

        ...

        // Set up the pipe for sending commands back to the parent process.

        int fd = atoi(argv[2]);
        FILE* cmd_pipe = fdopen(fd, "wb");
        setlinebuf(cmd_pipe);

        // Extract the script from the package.

        const char* package_filename = argv[3];
        MemMapping map;
        if (sysMapFile(package_filename, &map) != 0) {
            printf("failed to map package %s\n", argv[3]);
            return 3;
        }
        ZipArchive za;
        int err;
        err = mzOpenZipArchive(map.addr, map.length, &za);
        if (err != 0) {
            fprintf(stderr, "failed to open package %s: %s\n",
                   argv[3], strerror(err));
            return 3;
        }

        // META_INF/com/google/android/updater_script
        const ZipEntry* script_entry = mzFindZipEntry(&za, SCRIPT_NAME);
        if (script_entry == NULL) {
            printf("failed to find %s in %s\n", SCRIPT_NAME, package_filename);
            return 4;
        }

        char* script = malloc(script_entry->uncompLen+1);
        if (!mzReadZipEntry(&za, script_entry, script, script_entry->uncompLen)) {
            fprintf(stderr, "failed to read script from package\n");
            return 5;
        }
        script[script_entry->uncompLen] = '\0';
        // Configure edify's functions.

        RegisterBuiltins();
        RegisterInstallFunctions();
        RegisterBlockImageFunctions();
        RegisterDeviceExtensions();
        FinishRegistration();

        // Parse the script.

        Expr* root;
        int error_count = 0;
        // yacc语言写的东东没有高清楚语法，主要功能是将脚本命令转换成一个语法树
        int error = parse_string(script, &root, &error_count);
        if (error != 0 || error_count > 0) {
            fprintf(stderr, "%d parse errors\n", error_count);
            return 6;
        }

        struct selinux_opt seopts[] = {
          { SELABEL_OPT_PATH, "/file_contexts" }
        };

        sehandle = selabel_open(SELABEL_CTX_FILE, seopts, 1);

        if (!sehandle) {
            fprintf(stderr, "Warning:  No file_contexts\n");
            fprintf(cmd_pipe, "ui_print Warning: No file_contexts\n");
        }

        // Evaluate the parsed script.

        UpdaterInfo updater_info;
        updater_info.cmd_pipe = cmd_pipe;
        updater_info.package_zip = &za;
        updater_info.version = atoi(version);
        updater_info.package_zip_addr = map.addr;
        updater_info.package_zip_len = map.length;

        State state;
        state.cookie = &updater_info;
        state.script = script;
        state.errmsg = NULL;

        // root指向最后一条命令
        // 将语法树对应的命令转换成相应的函数调用
        // TODO 添加日志跟踪updater代码，edify.c中添加的日至无输出.
        // yacc，lex学习遗留问题，yylex调用位置，root数组及注册函数调用流程.
        char* result = Evaluate(&state, root);
        if (result == NULL) {

            ...

            return 7;
        } else {
            ...
        }

        ...
        return 0;
    }
    ```

    script作为string传给parse_string函数，解释器通过最左规约方式解析script字符串
将得到的Expr树的根节点指针保存到root里.接下来Evaluate函数会调用上述语法树节点中
的回调函数，在回调函数中又会去调用Evaluate函数,这样updater就完成了对脚本的解析.

2. updater中的parse_string函数深入了解

    parse_string函数中涉及到了lex和yacc相关知识，需要深入了解一下，才能够真正理解
语法树的构建过程，及updater工作过程的一些细节.
    这里先介绍一下yacc的基本知识及语法(效序列的规范称为语法):

[Yacc 与 Lex 快速入门](http://www.ibm.com/developerworks/cn/linux/sdk/lex/ "yacc 语法" )
[yacc(1)](http://www.freebsd.org/cgi/man.cgi?query=yacc&sektion=1 "yacc 手册" )
[一个Lex/Yacc完整的示例(可使用C++)](http://blog.csdn.net/huyansoft/article/details/8860224 "yacc 示例")
[linux flex 手册](http://blog.csdn.net/rabbiteatpumpkin/article/details/7267681 "flex 手册")

    >   lex和yacc结合可以生成一个语言的编译器，其中lex做词法分析，将源语言解释成
    词法符号，yacc得到lex扫描得到的词法序列做语法分析并赋予语义.
        yylex函数触发lex分析扫描，这是lex从标准输入获取输入，也可以使用其他函数触发
    分析扫描并使用输入缓冲区作为分析的输入.
        yyparse函数触发yacc做语法语义分析
        终端和非终端符号.
        终端符号一般是语言中的一些内建函数，操作符等不可在分的词法符号，一般大写.
    非终端符号一般表达式一类的可以在分的词法符号.
        语法格式.
        ```Yacc
        %{
        /* Global and header definitions required */
        /* 头文件和宏定义 */
        %}
        /* Declarations (Optional token definitions) */
        /* 声明选项句柄定义等 */
        %%
        /* Parsing ruleset definitions */
        /* 定义解释器语法规则，即定义相应源语言的语法规范 */
        %%
        /* Additional C source code */
        /* c代码 */
        ```

* parse_string函数

    对应文件: bootable/recovery/edify/parser.y

```Yacc
%{
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "expr.h"
#include "yydefs.h"
#include "parser.h"

extern int gLine;
extern int gColumn;

void yyerror(Expr** root, int* error_count, const char* s);
int yyparse(Expr** root, int* error_count);

struct yy_buffer_state;
void yy_switch_to_buffer(struct yy_buffer_state* new_buffer);
struct yy_buffer_state* yy_scan_string(const char* yystr);

%}

%locations

%union {
    char* str;
    Expr* expr;
    struct {
        int argc;
        Expr** argv;
    } args;
}

/* 定义词法符号及符号绑定的类型,绑定的类型只能是YYSTYPE(上面的%union)中定义的类型 */
%token AND OR SUBSTR SUPERSTR EQ NE IF THEN ELSE ENDIF
// STRING,BAD句柄绑定为str对象,下面的同理
%token <str> STRING BAD
%type <expr> expr
%type <args> arglist

/* yacc扩展特性，默认yyparse函数是无参的，这里定义了函数的参数 */
%parse-param {Expr** root}
%parse-param {int* error_count}
%error-verbose

/* declarations in increasing order of precedence 
 * 操作符优先级自上而下依次递增
 */
%left ';'
%left ','
%left OR
%left AND
%left EQ NE
%left '+'
%right '!'

%%

// 解析脚本规则,语法树根节点指针赋值给root
input:  expr           { *root = $1; }
;

// 语法方面expr可以由一个STRING组成，
// 语义方面为每个STRING句型的表达式分配空间并初始化
// 其中Literal作为默认函数返回name成员
expr:  STRING {
    $$ = malloc(sizeof(Expr));
    $$->fn = Literal;
    $$->name = $1;
    $$->argc = 0;
    $$->argv = NULL;
    $$->start = @$.start;
    $$->end = @$.end;
}

// @$,@1...@n和$$,$1...$n类似，潜者代表对yylloc的引用，后者代表对yylval的引用
|  '(' expr ')'                      { $$ = $2; $$->start=@$.start; $$->end=@$.end; }
|  expr ';'                          { $$ = $1; $$->start=@1.start; $$->end=@1.end; }

// 使用Build函数为当前表达式构建根结点，两个表达式的值作为根节点的两个参数，根
// 节点回调函数SequenceFn使用上述两个参数先后调用EvaluateValue函数，从而完成对
// 两个字节点的语义执行
|  expr ';' expr                     { $$ = Build(SequenceFn, @$, 2, $1, $3); }

// TODO error非终端符号和intput非终端符号都未定义或声明
|  error ';' expr                    { $$ = $3; $$->start=@$.start; $$->end=@$.end; }

// ConcatFn函数将参数的计算返回值按字符串形式拼接
|  expr '+' expr                     { $$ = Build(ConcatFn, @$, 2, $1, $3); }
|  expr EQ expr                      { $$ = Build(EqualityFn, @$, 2, $1, $3); }
|  expr NE expr                      { $$ = Build(InequalityFn, @$, 2, $1, $3); }
|  expr AND expr                     { $$ = Build(LogicalAndFn, @$, 2, $1, $3); }
|  expr OR expr                      { $$ = Build(LogicalOrFn, @$, 2, $1, $3); }
|  '!' expr                          { $$ = Build(LogicalNotFn, @$, 1, $2); }
|  IF expr THEN expr ENDIF           { $$ = Build(IfElseFn, @$, 2, $2, $4); }
|  IF expr THEN expr ELSE expr ENDIF { $$ = Build(IfElseFn, @$, 3, $2, $4, $6); }

/* 函数表达式初始化时根据注册的回调函数的函数名找到对应的函数指针给节点回调函数成员赋值 */
| STRING '(' arglist ')' {
    $$ = malloc(sizeof(Expr));
    $$->fn = FindFunction($1);
    if ($$->fn == NULL) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "unknown function \"%s\"", $1);
        yyerror(root, error_count, buffer);
        YYERROR;
    }
    $$->name = $1;
    $$->argc = $3.argc;
    $$->argv = $3.argv;
    $$->start = @$.start;
    $$->end = @$.end;
}
;

// 函数的参数列表可以是空,表达式,或者以逗号分隔的对个表达式
arglist:    /* empty */ {
    $$.argc = 0;
    $$.argv = NULL;
}
| expr {
    $$.argc = 1;
    $$.argv = malloc(sizeof(Expr*));
    $$.argv[0] = $1;
}
| arglist ',' expr {
    $$.argc = $1.argc + 1;
    $$.argv = realloc($$.argv, $$.argc * sizeof(Expr*));
    $$.argv[$$.argc-1] = $3;
}
;

%%

void yyerror(Expr** root, int* error_count, const char* s) {
  if (strlen(s) == 0) {
    s = "syntax error";
  }
  printf("line %d col %d: %s\n", gLine, gColumn, s);
  ++*error_count;
}

//函数比较简单，设置字符穿参数作为lex输入，触发lex及yacc解析
//关键在语法规则上
int parse_string(const char* str, Expr** root, int* error_count) {
    yy_switch_to_buffer(yy_scan_string(str));
    return yyparse(root, error_count);
}
```



