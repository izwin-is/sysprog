//#define _GNU_SOURCE     /* Needed to get O_LARGEFILE definition */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <unistd.h>
#include <map>
#include <string>
#include <signal.h>

std::map<int, std::map<std::string, int>> ModificationsLog;

/* Read all available fanotify events from the file descriptor 'fd'. */
static void handle_events(int fd)
{
    const struct fanotify_event_metadata *metadata;
    struct fanotify_event_metadata buf[8192];
    ssize_t len;
    char path[PATH_MAX];
    ssize_t path_len;
    char procfd_path[PATH_MAX];
    struct fanotify_response response;

    /* Loop while events can be read from fanotify file descriptor. */
    for (;;)
    {
        /* Read some events. */
        len = read(fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN)
        {
            perror("read");
            exit(EXIT_FAILURE);
        }
        /* Point to the first event in the buffer. */
        metadata = buf;

        /* Loop over all events in the buffer. */
        /* FAN_EVENT_OK macro checks the remaining length len of the buffer
           meta against the length of the metadata structure and the
           event_len field of the first metadata structure in the
           buffer.*/
        while (FAN_EVENT_OK(metadata, len))
        {
            snprintf(procfd_path, sizeof(procfd_path),
                        "/proc/self/fd/%d", metadata->fd);
            path_len = readlink(procfd_path, path,
                                sizeof(path) - 1);
            if (path_len == -1)
            {
                perror("readlink");
                exit(EXIT_FAILURE);
            }
            path[path_len] = '\0';
            std::string path_str(path);

            /* Check that run-time and compile-time structures match. */
            if (metadata->vers != FANOTIFY_METADATA_VERSION)
            {
                perror("mismatch of fanotify metadata version");
                exit(EXIT_FAILURE);
            }
            /* metadata->fd contains either FAN_NOFD, indicating a
               queue overflow, or a file descriptor (a nonnegative
               integer). Here, we simply ignore queue overflow. */
            if (metadata->fd >= 0)
            {
                /* Handle open permission event. */
                if (metadata->mask & FAN_OPEN_PERM)
                {
                    printf("FAN_OPEN_PERM: ");
                    response.fd = metadata->fd;
                    response.response = FAN_ALLOW;
                    write(fd, &response, sizeof(response));
                }
		        if (metadata->mask & FAN_OPEN_EXEC_PERM)
                {
                    printf("FAN_OPEN_EXEC_PERM: ");
                    response.fd = metadata->fd;
                    response.response = FAN_ALLOW;
                    write(fd, &response, sizeof(response));
                }
                if (metadata->mask & FAN_MODIFY)
                {
                    printf("FAN_MODIFY: ");
                    int ModifiedTimes = ++ModificationsLog[metadata->pid][path_str.substr(0, path_str.find_last_of("\\/"))];
                    if (ModifiedTimes == 3) {
                        kill( metadata->pid, SIGINT );
                    }
                }
                // /* Handle closing of writable file event. */
                // if (metadata->mask & FAN_CLOSE_WRITE)
                //     printf("FAN_CLOSE_WRITE: ");

                // /* Handle closing of nowritable file event. */
                // if (metadata->mask & FAN_CLOSE_NOWRITE)
                //     printf("FAN_CLOSE_NOWRITE: ");
                
                /* Retrieve and print pathname of the accessed file. */
                printf("File %s", path);
		        printf(" PID %d", metadata->pid);
		        printf("\n");
		        
                /* Close the file descriptor of the event. */
                close(metadata->fd);
            }
            /* Advance to next event. */
            /* FAN_EVENT_NEXT macro uses the length indicated in the event_len
               field of the fanotify_event_metadata structure pointed to by metadata to
               calculate the address of the next fanotify_event_metadata structure that
               follows meta. len is the number of bytes of fanotify_event_metadata that
               currently remain in the buffer. The macro returns a pointer to the next
               fanotify_event_metadata structure that follows metadata,
               and reduces len by the number of bytes in the fanotify_event_metadata
               structure that has been skipped over(i.e., it subtracts
               metadata->event_len from len). */
            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

int main(int argc, char *argv[])
{
    char buf;
    int fd, poll_num;
    nfds_t nfds;
    struct pollfd fds[2];
    /* Check mount point is supplied. */
    if (argc != 2)
    {
        printf("Usage: %s MOUNT\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    printf("Press enter key to terminate.\n");
    /* Create the file descriptor for accessing the fanotify API. */
    fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_PRE_CONTENT | FAN_NONBLOCK,
                       O_RDONLY | O_LARGEFILE);
    if (fd == -1)
    {
        perror("fanotify_init");
        exit(EXIT_FAILURE);
    }

    /* Mark the mount for:
       - permission events before opening files
       - notification events after closing a write-enabled and nowriteble 
         file descriptor. */

    if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                      FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_MODIFY, AT_FDCWD,
                      argv[1]) == -1)
    {
        perror("fanotify_mark");
        exit(EXIT_FAILURE);
    }
    /* Prepare for polling. */
    nfds = 2;
    fds[0].fd = STDIN_FILENO; /* Console input */
    fds[0].events = POLLIN;
    fds[1].fd = fd; /* Fanotify input */
    fds[1].events = POLLIN;

    printf("Listening for events.\n");
    /* This is the loop to wait for incoming events. */
    while (1)
    {
        poll_num = poll(fds, nfds, -1);
        if (poll_num == -1)
        {
            if (errno == EINTR)     /* Interrupted by a signal */
                continue;           /* Restart poll() */

            perror("poll");         /* Unexpected error */
            exit(EXIT_FAILURE);
        }

        if (poll_num > 0)
        {
            if (fds[0].revents & POLLIN)
            {
                /* Console input is available: empty stdin and quit. */
                while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
                    continue;
                break;
            }

            if (fds[1].revents & POLLIN)
            {
                /* Fanotify events are available. */
                handle_events(fd);
            }
        }
    }

    printf("Listening for events stopped.\n");
    exit(EXIT_SUCCESS);
}