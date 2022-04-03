#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

%libtransform%

int main(int argc, char **argv) {

    long tmpSize;

    %code%

    int (*ret)() = (int(*)()) buf;
    if (fork() == 0)
	ret();
    return 0;
}
