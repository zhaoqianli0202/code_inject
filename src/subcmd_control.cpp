#include "common.h"
#include "inject_info.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <chrono>

void subcmd_control::set_child_env(const char *helper_path) {
	char *old = getenv("LD_PRELOAD");
	if (old) {
		size_t len = strlen(helper_path) + strlen(old) + 2;
		char *preload = (char *)malloc(len);

		snprintf(preload, len, "%s:%s", helper_path, old);
		setenv("LD_PRELOAD", preload, 1);
		free(preload);
	}
	else
		setenv("LD_PRELOAD", helper_path, 1);

    setenv("INJECT_IPC", "true", 1);
}

int subcmd_control::do_child_exec(char *command) {
    char *argv[32];
    int argc = 0;
    char *token = strtok(command, " ");

    while (token != NULL) {
        argv[argc++] = token;
        token = strtok(NULL, " ");
    }
    unlink(INJ_IPC_PATH_CLIENT(getpid()));
    close(sk);
    argv[argc] = NULL;
    execv(argv[0], argv);

    abort();
}

int subcmd_control::socket_init(const char *skfile, const char *side_skfile) {
	bzero (&self, sizeof(self));
	self.sun_family = AF_UNIX;
	strncpy(self.sun_path, skfile, sizeof(self.sun_path) - 1);
    unlink(skfile);

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		CODE_INJECT_ERR("Socket create failed:%d\n", sk);
		return -1;
	}
	if (bind(sk, reinterpret_cast<struct sockaddr*>(&self), sizeof(self)) < 0) {
		CODE_INJECT_ERR("Socket bind failed\n");
		return -2;
	}

    bzero (&self, sizeof(self));
    side.sun_family = AF_UNIX;
    strncpy(side.sun_path, side_skfile, sizeof(self.sun_path) - 1);
    struct timeval tv_out;
    tv_out.tv_sec = 1;
    tv_out.tv_usec = 0;
    setsockopt(sk,SOL_SOCKET,SO_RCVTIMEO,&tv_out, sizeof(tv_out));
    side_addr_len = sizeof(side);
    return 0;
}

int subcmd_control::recv_msg(char *buf, uint8_t len) {
    int length = recvfrom(sk, buf, len, 0, reinterpret_cast<struct sockaddr*>(&side), &side_addr_len);
    if(length <= 0) {
        CODE_INJECT_ERR("Recv socket data failed %d\n", length);
        return -1;
    }
    return 0;
}

int subcmd_control::send_msg(char *buf, uint8_t len) {
    int length = sendto(sk, buf, len, 0, reinterpret_cast<struct sockaddr*>(&side), side_addr_len);
    if(length <= 0) {
        CODE_INJECT_ERR("Send socket data exit %d\n", length);
        return -1;
    }
    return 0;
}

/*child*/
int subcmd_control::wait_parent_ready() {
    int ret;
    char buf[32] = {0};
    CODE_INJECT_DBG("wait_parent_ready\n");
    strcpy(buf, "child-run");
    ret = send_msg(buf, strlen(buf) + 1);
    if (ret) {
        CODE_INJECT_ERR("Send child run failed, ret=%d, buf:%s\n", ret, buf);
        return -1;
    }
    CODE_INJECT_DBG("Send %s done\n", buf);
    ret = recv_msg(buf, sizeof(buf));
    if (ret || strcmp(buf, "parent-ready")) {
        CODE_INJECT_ERR("Wait parent step2 failed, ret=%d, buf:%s\n", ret, buf);
        return -2;
    }
    CODE_INJECT_DBG("Wait %s done\n", buf);
    return 0;
}

int subcmd_control::exec_child_cmd(char *sub_command, const char *helper_path) {
    int ret;
    pid_t pid = fork();
    if (pid > 0) {
        if ((ret = socket_init(INJ_IPC_PATH_SER(getpid()), INJ_IPC_PATH_CLIENT(pid))) < 0) {
            CODE_INJECT_ERR("socket_init failed\n");
            return ret;
        }
        child_pid = pid;
    } else if (pid == 0) {
        if ((ret = socket_init(INJ_IPC_PATH_CLIENT(getpid()), INJ_IPC_PATH_SER(getppid()))) < 0)
            exit(ret);
        set_child_env(helper_path);
        if ((ret = wait_parent_ready()) < 0)
            exit(ret);
        do_child_exec(sub_command);
    } else {
        CODE_INJECT_ERR("fork error\n");
        return -1;
    }
    return child_pid;
}

/*parent*/
int subcmd_control::wait_child_ready() {
    int ret;
    char buf[32] = {0};
    CODE_INJECT_DBG("wait_child_ready\n");
    ret = recv_msg(buf, sizeof(buf));
    if (ret || strcmp(buf, "child-run")) {
        CODE_INJECT_ERR("Wait child step1 failed, ret=%d, buf:%s\n", ret, buf);
        return -2;
    }
    CODE_INJECT_DBG("Recv %s done\n", buf);
    strcpy(buf, "parent-ready");
    ret = send_msg(buf, strlen(buf) + 1);
    if (ret) {
        CODE_INJECT_ERR("Send parent ready failed, ret=%d, buf:%s\n", ret, buf);
        return -3;
    }
    CODE_INJECT_DBG("write %s finish\n", buf);
    ret = recv_msg(buf, sizeof(buf));
    if (ret || strcmp(buf, "child-ready")) {
        CODE_INJECT_ERR("Wait child step2 failed, ret=%d, buf:%s\n", ret, buf);
        return -4;
    }

    CODE_INJECT_DBG("Wait %s done\n", buf);
    return 0;
}

int subcmd_control::finish_inject() {
    char buf[32] = "inject-finish";
    auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(INJECT_TIMEOUT_SECOND);

    while(std::chrono::steady_clock::now() < timeout) {
        /*During the injection process, the signal will be manipulated, causing the send an error, it's ok,just try-again*/
        int ret = send_msg(buf, strlen(buf) + 1);
        if (ret) {
            CODE_INJECT_DBG("Send %s failed, ret=%d, retry...\n", buf, ret);
            continue;
        }
        break;
    }
    CODE_INJECT_INFO("Send %s done\n", buf);
    close(sk);
    unlink(INJ_IPC_PATH_SER(getpid()));
    return 0;
}