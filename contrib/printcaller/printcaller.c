#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#define N 1024
int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
    return EXIT_FAILURE;
  }
  char *file_path = argv[1];
  printf("pid: %d\n", getpid());
  printf("uid: %u\n", getuid());
  printf("euid: %u\n", geteuid()); // e == effective
  printf("gid: %u\n", getgid());
  printf("egid: %u\n", getegid());
  int fd = open(file_path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "Error opening file: '%s': %s\n", file_path, strerror(errno));
    return EXIT_FAILURE;
  }
  char buf[N];
  ssize_t bytes_read = read(fd, buf, N);
  if (bytes_read < 0) {
    fprintf(stderr, "Error opening file: '%s': %s\n", file_path, strerror(errno));
    close(fd);
    return EXIT_FAILURE;
  }
  printf("Read done\n");
  close(fd);
}
