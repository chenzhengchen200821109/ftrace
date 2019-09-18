// Instrumentation source -- link this with your application with  
//
//
//
#include "config.h"
#include <stdbool.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h> //wait
#include <unistd.h>

#pragma GCC visibility push(hidden)
#include "bfd.h"
#include "bucomm.h"
#include "demangle.h"
#include "libiberty.h"
#pragma GCC visibility pop 

//
//#define TRACE_BUF_LEN (127)
#define BUFLEN 256  
//default target for BFD library.
#define TARGET "i686-pc-linux-gnu"

typedef struct _libtrace_data 
{
    asymbol **syms;              /* Symbol table.  */
    bfd *abfd;
    asection *section;
} libtrace_data;

static libtrace_data m_libtrace_data = 
{
    .syms = NULL,
    .abfd = NULL,
    .section = NULL,
};

//These variables are used to pass information between
//translate_addresses() and find_address_in_section().
typedef struct _sym_info {
    bfd_vma pc;
    const char *file_name;
    const char *function_name;
    unsigned int line;
    bfd_boolean found;
} sym_info;

static char exec[256];
static char caller[256];
static int depth; //调用深度
static FILE* file;

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

//Function prototypes with attributes */
void main_constructor(void)
    __attribute__((no_instrument_function, constructor));
void main_destructor(void)
    __attribute__((no_instrument_function, destructor));
void __cyg_profile_func_enter(void *, void *)
    __attribute__((no_instrument_function));
void __cyg_profile_func_exit(void *, void *)
    __attribute__((no_instrument_function));

void get_exec_name(char* name, size_t len)
{
    char proc_file[256] = { 0 };
    pid_t pid = getpid();
    FILE* fd;

    snprintf(proc_file, 256, "/proc/%d/cmdline", pid);
    if ((fd = fopen(proc_file, "r")) == NULL) {
        fprintf(stderr, "Cannot open %s for reading: %s\n", proc_file, strerror(errno));
        exit(EXIT_FAILURE);        
    }
    if (!fgets(name, len, fd)) {
        fprintf(stderr, "fgets() failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    fclose(fd);
}

//========================================================================

void bfd_nonfatal(const char* string)
{
    const char *errmsg = bfd_errmsg (bfd_get_error ());

    if (string)
        fprintf(stderr, "%s: %s: %s\n", exec, string, errmsg);
    else
        fprintf(stderr, "%s: %s\n", exec, errmsg);
}

// Look for an address in a section. This is called via bfd_map_over_sections.
static void find_address_in_section(bfd *abfd, asection *section, void *data)
{
    bfd_vma vma;
    bfd_size_type size;
    sym_info* psi = (sym_info *)data;

    //already found.
    if (psi->found)
        return;

    if ((bfd_get_section_flags(abfd, section) & (SEC_ALLOC | SEC_CODE)) == 0) //SEC_ALLOC
        return;

    //vma表示基地址。
    vma = bfd_get_section_vma(abfd, section);
    if (psi->pc < vma)
        return;

    size = bfd_get_section_size(section);
    if (psi->pc >= vma + size)
        return;

    psi->found = bfd_find_nearest_line(abfd, section,
                   m_libtrace_data.syms, psi->pc - vma,
                   &psi->file_name, &psi->function_name,
                   &psi->line);
}

/* Look for an offset in a section.  This is directly called.  */
static void find_offset_in_section(bfd *abfd, asection *section, sym_info *psi)
{
    bfd_size_type size;
  
    if (psi->found)
        return;
  
    if ((bfd_get_section_flags(abfd, section) & (SEC_ALLOC | SEC_CODE)) == 0)
        return;
  
    size = bfd_get_section_size(section);
    if (psi->pc >= size)
        return;
  
    psi->found = bfd_find_nearest_line(abfd, section,
                      m_libtrace_data.syms, psi->pc,
                      &psi->file_name, &psi->function_name,
                      &psi->line);
  }

/* Translate addr into file_name:line_number and optionally function name.  */
static int translate_address(bfd *abfd, asection *section, void *xaddr, char *buf_func, 
        size_t func_len, char *buf_file, size_t file_len, unsigned int* linenum)
{
    char addr[16] = { 0 };
    sym_info si = { 0 };
    char* sym = NULL;

    //bfd_scan_vma(): convert a numerical expression into a integer.
    sprintf(addr, "%p", xaddr);
    si.pc = bfd_scan_vma (addr, NULL, 16);

    si.found = false;
    if (section)
        find_address_in_section(abfd, section, &si);
    else
        bfd_map_over_sections(abfd, find_address_in_section, &si);

    if (si.found) {
        //如果没有demangle， 那么bfd_demangle返回NULL
        if ((sym = bfd_demangle(abfd, si.function_name, DMGL_GNU_V3))) {
            snprintf(buf_func, func_len, "%s", sym);
            free(sym);
        } else {
            strncpy(buf_func, si.function_name, func_len);
        }
        strncpy(buf_file, si.file_name, file_len);
        *linenum = si.line;
    }
    return si.found;
}

/* Set the default BFD target based on the configured target.  Doing
   this permits the binutils to be configured for a particular target,
   and linked against a shared BFD library which was configured for a
   different target.  */
void set_default_bfd_target(void)
{
    /* The macro TARGET is defined by Makefile.
       E.g.: -DTARGET='"i686-pc-linux-gnu"'.  */
    const char *target = TARGET;

    if (! bfd_set_default_target (target)) {
        fprintf(stderr, "can't set BFD default target to `%s': %s", target, bfd_errmsg (bfd_get_error ()));
    }
}

//
int libtrace_init(const char *prog_name, const char *section_name, const char* target)
{
    char **matching = NULL;
    bfd* ret = NULL;
    asection* psection = NULL;

    //initialize a BFD
    bfd_init();
    //
    set_default_bfd_target();

    if ((ret = bfd_openr(prog_name, target)) == NULL) {
        bfd_nonfatal ("bfd_openr() failed");
        return -1;
    }

    m_libtrace_data.abfd = ret;
    if (!bfd_check_format_matches(m_libtrace_data.abfd, bfd_object, &matching)) {
        bfd_nonfatal("bfd_check_format_matches() failed");
        return -1;
    }

    if (section_name != NULL) {
        if ((psection = bfd_get_section_by_name(m_libtrace_data.abfd, section_name)) == NULL) {
            bfd_nonfatal("bfd_get_section_by_name");
            return -1;
        }
    }

    m_libtrace_data.section = psection;
    return 0;
}

//
int libtrace_close(void)
{
    if (m_libtrace_data.syms != NULL) {
        free(m_libtrace_data.syms);
        m_libtrace_data.syms = NULL;
    }

    bfd_close(m_libtrace_data.abfd);
    return 0;
}

//
static int libtrace_resolve(void* addr, char* buf_func, size_t len_func, 
        char* buf_file, size_t len_file, unsigned int* linenum)
{
    return translate_address(m_libtrace_data.abfd, m_libtrace_data.section,
            addr, buf_func, len_func, buf_file, len_file, linenum);
}

void print_format(int num)
{
    fprintf(file, "| ");
    for (int i = 0; i < num; i++) {
        fprintf(file, "| ");
    }
}

void print_end(int num, const char* tag)
{
    fprintf(file, "| ");
    for (int i = 0; i < num; i++)
        fprintf(file, "| ");
    fprintf(file, "================================ %s ================================\n", tag);
}

int isInValidFunc(const char* file_name)
{
    //Ubuntu系统自带的gcc头文件所在目录。
    if (strstr(file_name, "/usr/include/") == file_name)
        return 1;
    //以防用户像我一样安装另一个版本的gcc在以下目录。
    else if (strstr(file_name, "/usr/local/") == file_name)
        return 1;
    else
        return 0;
}

// ===========================================================================================

void main_constructor(void)
{
    int pipefd[2];
    pid_t pid;

    //获取可执行文件的文件名。
    get_exec_name(exec, 256);

    if (libtrace_init(exec, ".text", NULL) != 0) {
        fprintf(stderr, "libtrace_init() failed.");
        exit(EXIT_FAILURE);
    }

    if ((file = fopen("data.txt", "w")) == NULL) {
        fprintf(stderr, "fopen() failed.");
        exit(EXIT_FAILURE);
    }
    printf("======write trace result to file data.txt======\n\n");
    fprintf(file, "================================ FUNCTION ================================\n");
}

void main_destructor(void)
{
    print_end(1, "end");
    fclose(file);
    libtrace_close();
}

void __cyg_profile_func_enter(void* this_func, void* call_site)
{
    char callee_func[BUFLEN] = { 0 };
    char callee_file[BUFLEN] = { 0 };
    unsigned int callee_line;
    char caller_func[BUFLEN] = { 0 };
    char caller_file[BUFLEN] = { 0 };
    unsigned int caller_line;
    int* frame = NULL;
    char* p;

    if (!file)
        return;
    if (!m_libtrace_data.abfd)
        return;
    frame = (int *)__builtin_frame_address(1);
    assert(frame != NULL);

    libtrace_resolve(this_func, callee_func, BUFLEN, callee_file, BUFLEN, &callee_line);
    libtrace_resolve(call_site, caller_func, BUFLEN, caller_file, BUFLEN, &caller_line);

    //从main()函数开始追踪。
    if (!(strncmp(callee_func, "__static_initialization_and_destruction_0", 41))) 
        return;
    if ((callee_func[0] == '\0') && (caller_func[0] == '\0'))
        return;
    if ((strncmp(callee_func, "main", 4)) && (caller_func[0] == '\0'))
        return;

    if (isInValidFunc(callee_file)) 
        return;
    //if (isInValidFunc(caller_func))
    //    return;
    p = strrchr(callee_file, '/');
    print_format(depth);
    if (p) {
        p++;
        fprintf(file, "%s() file: %s, line: %d\n", callee_func, p, callee_line);
    } else {
        fprintf(file, "%s() file: unkown, line: %d\n", callee_func, callee_line);
    }
    depth++;
    //Used for debug.
    //fprintf(file, "Enter: \n");
    //fprintf(file, "%s() file: %s, line: %d\n", callee_func, callee_file, callee_line);
}

void __cyg_profile_func_exit(void* this_func, void* call_site)
{
    //
    char callee_func[BUFLEN] = { 0 };
    char callee_file[BUFLEN] = { 0 };
    unsigned int callee_line;
    char caller_func[BUFLEN] = { 0 };
    char caller_file[BUFLEN] = { 0 };
    unsigned int caller_line;
    int* frame = NULL;

    if (!m_libtrace_data.abfd)
        return;
    frame = (int *)__builtin_frame_address(1);
    assert(frame != NULL);

    libtrace_resolve(this_func, callee_func, BUFLEN, callee_file, BUFLEN, &callee_line);
    libtrace_resolve(call_site, caller_func, BUFLEN, caller_file, BUFLEN, &caller_line);

    if (!(strncmp(callee_func, "__static_initialization_and_destruction_0", 41))) 
        return;
    if ((callee_func[0] == '\0') && (caller_func[0] == '\0'))
        return;
    if ((strncmp(callee_func, "main", 4)) && (caller_func[0] == '\0'))
        return;

    if (isInValidFunc(callee_file))
        return;
    //if (isInValidFunc(caller_func))
    //    return;
    depth--;
    if (depth == 2)
        print_end(depth, "ret");
    //Used for debug.
    //fprintf(file, "Exit: \n");
    //fprintf(file, "%s() file: %s, line: %d\n", callee_func, callee_file, callee_line);
}

#ifdef __cplusplus
}
#endif //__cplusplus
