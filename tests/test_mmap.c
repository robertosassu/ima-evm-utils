#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/personality.h>

int main(int argc, char *argv[])
{
	struct stat st;
	void *ptr, *ptr_write = NULL;
	int ret, fd, fd_write, prot = PROT_READ;

	if (!argv[1])
		return -ENOENT;

	if (argv[2] && !strcmp(argv[2], "read_implies_exec")) {
		ret = personality(READ_IMPLIES_EXEC);
		if (ret < 0)
			return ret;
	}

	if (stat(argv[1], &st) == -1)
		return -errno;

	if (argv[2] && !strcmp(argv[2], "exec_on_writable")) {
		fd_write = open(argv[1], O_RDWR);
		if (fd_write == -1)
			return -errno;

		ptr_write = mmap(0, st.st_size, PROT_WRITE, MAP_SHARED,
				 fd_write, 0);
		close(fd_write);

		if (ptr_write == (void *)-1)
			return -errno;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		if (ptr_write)
			munmap(ptr_write, st.st_size);

		return -errno;
	}

	if (argv[2] && !strncmp(argv[2], "exec", 4))
		prot |= PROT_EXEC;

	ptr = mmap(0, st.st_size, prot, MAP_PRIVATE, fd, 0);

	close(fd);

	if (ptr_write)
		munmap(ptr_write, st.st_size);

	if (ptr == (void *)-1)
		return -errno;

	ret = 0;

	if (argv[2] && !strcmp(argv[2], "mprotect"))
		ret = mprotect(ptr, st.st_size, PROT_EXEC);

	munmap(ptr, st.st_size);
	return ret;
}
