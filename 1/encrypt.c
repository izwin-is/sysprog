#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <unistd.h>
#include <utime.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

void signal_handler(int s)
{
	printf("encryptor was killed\n");
	exit(1);
}

int encrypt_files(const char* path, char key) {
  int status = 0;
  const int n = PATH_MAX;
  struct dirent *entry = NULL;
  DIR *dir = NULL;
  DIR *sub_dir = NULL;
  FILE *fp = NULL;
  unsigned int sz = 0;
  unsigned int sz_read = 0;
  unsigned int sz_write = 0;
  char* fdata = NULL;
  char abs_path[PATH_MAX];
  dir = opendir(path);
  if (dir) {
    while (entry = readdir(dir)) {
      sub_dir = NULL;
      fp = NULL;
      memset(abs_path, 0, PATH_MAX);
      if ((entry->d_name[0] == '.' && strlen(entry->d_name) == 1) || ((strlen(entry->d_name) == 2) && (entry->d_name[0] == '.') && (entry->d_name[1] == '.')))
        continue;
      
      snprintf(abs_path, n, "%s/%s", path, entry->d_name);
      if (sub_dir = opendir(abs_path)) {
        closedir(sub_dir);
        encrypt_files(abs_path, key);
        continue;
      }
      if (fp = fopen(abs_path, "r")) {
        fseek(fp, 0L, SEEK_END);
        sz = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        fdata = malloc(sizeof(char)*sz);
        if (!fdata) {
          status = errno;
          printf("Allocation for %d bytes failed wit herror %d!\n", sz, status);
          return status;
        }
        sz_read = fread(fdata, 1, sz, fp);
        if (sz != sz_read) {
          printf("File %s size is %d, but has been read %d \n", abs_path, sz, sz_read);
        }
        fclose(fp);
	    if (fp = fopen(abs_path,"w")) {
	      for (int i = 0; i < sz; ++i){
	        fdata[i] ^= key;
	      }
	      sz_write = fwrite(fdata, 1, sz_read, fp);
          if (sz != sz_write) {
            printf("buffer size is %d, but has been written %d \n", sz_read, sz_write);
          }
	      free(fdata);
          fclose(fp);
	    }
      }
    }
  }
  return status;
}

int main(int argc, char* argv[]) {
  signal(SIGINT, signal_handler);

  int ret = 0;
  /* Check cmd params*/
  if (argc != 3) {
    printf("usage: %s path key\n", argv[0]);
    return 1;
  }
  ret = encrypt_files(argv[1], (char)atoi(argv[2]));
  printf("encrypting finished with code %d\n", ret);

  usleep(10000);
  return ret;
}