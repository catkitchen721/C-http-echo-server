#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define STR_IMPL(n, s) "\033["#n"m"s"\033[0m"
#define STR_SUCCESS(s) STR_IMPL(32, s)
#define STR_FAILED(s) STR_IMPL(31, s)
#define BUF_SIZE 32768

#define CRLF "\r\n"
#define STATUS_CODE(n) #n
#define STATUS_INFO(s) s
#define HTTP_VERSION "1.1"
#define HTTP_STARTLINE(n, s) "HTTP/" HTTP_VERSION " " STATUS_CODE(n) " " STATUS_INFO(s) CRLF
#define HTTP_HEADER(type, opts) "Content-Type: "type CRLF opts

struct sockaddr_in addr_info;
struct sockaddr_in c_addr_info;
socklen_t addr_len;
socklen_t c_addr_len;
int socket_fd;
int c_socket_fd;

char *request_startline = NULL;
char **request_headers = NULL;
size_t request_headers_len = 0;
char *request_path = NULL;

int get_request_path_index(const char *req_sl)
{
    int i=0;
    while(req_sl[i]!=' ' && req_sl[i]!='\0')
    {
        i++;
    }
    return i+1;
}

char *get_substr(const char *s, int pos, size_t len) /* please free it after using */
{
    char *s_ret = (char *)malloc(sizeof(char) * (len+1));
    if(!s_ret)
    {
        perror("malloc failed");
        return NULL;
    }
    
    strncpy(s_ret, (const char *)(((uintptr_t)s) + ((uintptr_t)pos)), len);
    s_ret[len] = '\0';
    return s_ret;
}

bool is_favicon(const char *req_path)
{
    if(strlen(req_path) < 8) return false;
    char *substr = get_substr(req_path, 1, 7);
    #ifndef NDEBUG
    printf("\nsubstr: %s\n", substr);
    #endif
    if(strcmp(substr, "favicon") == 0)
    {
        free(substr);
        return true;
    }
    free(substr);
    return false;
}

void ctrl_c_handler(int signum)
{
    if(request_startline) free(request_startline);
    if(request_headers) free(request_headers);
    if(request_path) free(request_path);
    printf("\nAllocated memory freed.\n");
    shutdown(c_socket_fd, SHUT_RDWR);
    shutdown(socket_fd, SHUT_RDWR);
    close(c_socket_fd);
    close(socket_fd);
    printf("All sockets closed.\n");
    signal(signum, SIG_DFL);
    kill(getpid(), signum);
}

int main(int argc, char *argv[])
{
    socket_fd = socket(PF_INET, SOCK_STREAM, 0);
    signal(SIGINT, ctrl_c_handler);
    if(socket_fd < 0)
    {
        perror(STR_FAILED("socket created failed"));
        exit(EXIT_FAILURE);
    }
    memset(&addr_info, 0, sizeof(struct sockaddr_in));
    addr_info.sin_family = AF_INET;
    addr_info.sin_port = htons(8888);
    addr_info.sin_addr.s_addr = INADDR_ANY;
    addr_len = sizeof(struct sockaddr);

    int can_reuse = 1;
    if(setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &can_reuse, sizeof(can_reuse)) < 0)
    {
        perror(STR_FAILED("setsockopt failed"));
        close(socket_fd);
        exit(EXIT_FAILURE);
    }
    if(bind(socket_fd, (struct sockaddr *)&addr_info, addr_len))
    {
        perror(STR_FAILED("binding failed"));
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    if(listen(socket_fd, 5))
    {
        perror(STR_FAILED("listening error or queue is full"));
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    do
    {
        printf("\nListening on port 8888...\n");
        printf("(To interupt the server please press Ctrl-C.)\n");
        memset(&c_addr_info, 0, sizeof(struct sockaddr_in));
        if((c_socket_fd = accept(socket_fd, (struct sockaddr *)&c_addr_info, &c_addr_len)) < 0)
        {
            perror(STR_FAILED("accepting error"));
            close(socket_fd);
            exit(EXIT_FAILURE);
        }
        char buf[BUF_SIZE] = "";
        size_t curr_buf_len = 0;
        if(recv(c_socket_fd, buf, BUF_SIZE, 0) < 0)
        {
            perror(STR_FAILED("recv failed"));
        }

        char buf_clone[BUF_SIZE] = "";
        strcpy(buf_clone, buf);

        char *tmp_s = NULL;
        tmp_s = strtok(buf_clone, CRLF);
        if(tmp_s)
        {
            request_startline = strdup(tmp_s);
        }
        else
        {
            request_startline = NULL;
        }

        do {
            tmp_s = strtok(NULL, CRLF);
            if(tmp_s)
            {
                void *tmp_ptr = realloc(request_headers, (request_headers_len + 1) * sizeof(char *));
                if(!tmp_ptr)
                {
                    perror(STR_FAILED("realloc failed"));
                    close(socket_fd);
                    close(c_socket_fd);
                    exit(EXIT_FAILURE);
                }
                request_headers_len += 1;
                request_headers = (char **)tmp_ptr;
                tmp_ptr = NULL;
                request_headers[request_headers_len - 1] = tmp_s;
            }
        }while(tmp_s);

        /* printf("\nReceive from client:\n================================\n\n%s================================\n", buf); */
        printf("\n"STR_SUCCESS("request_startline:  %s")"\n", request_startline);

        int request_path_index = get_request_path_index(request_startline);
        if(request_path_index < 0 || (size_t)request_path_index >= strlen(request_startline))
        {
            perror(STR_FAILED("get_request_path_index failed"));
            close(socket_fd);
            close(c_socket_fd);
            exit(EXIT_FAILURE);
        }
        request_path = strdup(request_startline);
        char *real_request_path = (char *)((uintptr_t)request_path + (uintptr_t)request_path_index);
        size_t i_s;
        for(i_s=0; i_s<strlen(real_request_path);i_s++)
        {
            if(real_request_path[i_s] == ' ') 
            {
                real_request_path[i_s] = '\0';
                break;
            }
        }
        #ifndef NDEBUG
        printf("[%s]\n", real_request_path);
        #endif

        memset(buf, 0, BUF_SIZE);
        curr_buf_len = 0;
        if(!is_favicon(real_request_path))
        {
            #ifndef NDEBUG
            printf("\n%s: no\n", real_request_path);
            #endif
            strcpy(buf, HTTP_STARTLINE(200, "OK") HTTP_HEADER("text/html; charset=UTF-8", "") CRLF);
            
            size_t i = 0;
            bool is_query = false;
            char *query_s = NULL;
            char empty_query_s[1] = "";
            for(i=0; i<strlen(real_request_path); i++)
            {
                if(real_request_path[i] == '=')
                {
                    is_query = true;
                    if(i == strlen(real_request_path) - 1)
                    {
                        query_s = empty_query_s;
                    }
                    else
                    {
                        query_s = real_request_path + i + 1;
                    }
                    break;
                }
            }
            curr_buf_len = strlen(buf);
            if(!is_query)
            {
                FILE *page = fopen("./templates/index.html", "r");
                while(curr_buf_len < BUF_SIZE)
                {
                    char c = 0;
                    if((c = fgetc(page)) == EOF)
                    {
                        break;
                    }
                    buf[curr_buf_len] = c;
                    curr_buf_len++;
                }
                fclose(page);
            }
            else
            {
                FILE *page = fopen("./templates/index.html.first", "r");
                while(curr_buf_len < BUF_SIZE)
                {
                    char c = 0;
                    if((c = fgetc(page)) == EOF)
                    {
                        break;
                    }
                    buf[curr_buf_len] = c;
                    curr_buf_len++;
                }
                fclose(page);
                size_t i = 0;
                for(i=0; i<strlen(query_s); i++)
                {
                    buf[curr_buf_len] = query_s[i];
                    curr_buf_len++;
                }
                page = fopen("./templates/index.html.second", "r");
                while(curr_buf_len < BUF_SIZE)
                {
                    char c = 0;
                    if((c = fgetc(page)) == EOF)
                    {
                        break;
                    }
                    buf[curr_buf_len] = c;
                    curr_buf_len++;
                }
                fclose(page);
            }
        }
        else
        {
            #ifndef NDEBUG
            printf("\n%s: yes\n", real_request_path);
            #endif
            strcpy(buf, HTTP_STARTLINE(200, "OK") HTTP_HEADER("image/x-icon", /*"Content-Length: 4286" CRLF "Accept-Ranges: bytes" CRLF*/"") CRLF);
            curr_buf_len = strlen(buf);
            int i = 0;
            FILE *ico = fopen("./favicon.ico", "rb");
            while(i < 4286 && curr_buf_len < BUF_SIZE)
            {
                buf[curr_buf_len] = fgetc(ico);
                curr_buf_len++;
                i++;
            }
            fclose(ico);
        }

        if(request_startline) 
        {
            free(request_startline);
            request_startline = NULL;
        }
        if(request_headers)
        {
            free(request_headers);
            request_headers = NULL;
        }
        if(request_path)
        {
            free(request_path);
            request_path = NULL;
        }

        #ifndef NDEBUG
        printf("\n"STR_SUCCESS("%s\n\n%lu")"\n", buf, curr_buf_len);
        #endif
        if(send(c_socket_fd, buf, curr_buf_len, 0) < 0)
        {
            perror(STR_FAILED("send failed"));
        }

        shutdown(c_socket_fd, SHUT_RDWR);
        close(c_socket_fd);
    }while(1);

    if(request_startline) free(request_startline);
    if(request_headers) free(request_headers);
    if(request_path) free(request_path);
    shutdown(c_socket_fd, SHUT_RDWR);
    shutdown(socket_fd, SHUT_RDWR);
    close(c_socket_fd);
    close(socket_fd);
    return 0;
}