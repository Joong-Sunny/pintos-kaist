#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
// #include "filesys/file.c"
#include "threads/init.h"
#include "userprog/process.h"
#include "devices/input.h"
void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static int64_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED ) {
	// TODO: Your implementation goes here.
	// 유저 스택에 저장되어 있는 시스템 콜 넘버를 이용해 시스템 콜 핸들러 구현
	// 스택 포인터가 유저 영역인지 확인
	// check_address(f->rsp);
	// printf("== f->R.rax== %d \n", f->R.rax);
	switch (f->R.rax) {
		case SYS_HALT:
			halt();
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_EXIT:
			// printf("== f->R.rdi== %d \n", f->R.rdi);
			// printf("== f->R.rdx== %d \n", f->R.rdx);
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax =  fork(f->R.rdi);
			break;
		// case SYS_EXEC:
		// 	exec(f->R.rdi);
		// 	break;
		case SYS_WAIT:
			// TODO: 종료되었는지 확인?
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			// printf("=== get_user result = %d\n", get_user(f->R.rdi));
			if (f->R.rdi == NULL || get_user (f->R.rdi) == -1 || is_kernel_vaddr(f->R.rdi)) {
				exit(-1);
			}
			else {
				f->R.rax = create(f->R.rdi, f->R.rsi) ? 1 : 0;
			}
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi) ? 1 : 0;
			break;
		case SYS_OPEN:
			// printf("==== f->R.rdi = %s\n", f->R.rdi);
			// printf("==== f->R.rsi = %d\n", f->R.rsi);
			// printf("==== f->R.rdx = %d\n", f->R.rdx);
			if (f->R.rdi == NULL) {
				exit(-1);
			}
			int result = open(f->R.rdi);
			f->R.rax = result == NULL ? -1 : result;
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		// case SYS_SEEK:
		// 	seek();
		// 	break;
		// case SYS_TELL:
		// 	tell();
		// 	break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			// thread_exit()
			break;
	}
}

// TBD chobae : pintos syscall func add
void check_address(void *addr)	{
	/*  포인터가 가리키는 주소가 유저영역의 주소인지 확인
		잘못된 접근일 경우 프로세스 종료
		유효한 주소 (0x8048000 ~ 0x0000000)인지 확인
	*/
	if (is_kernel_vaddr(addr)) {
		thread_exit();
	}
}

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
    "movabsq $done_get, %0\n"
    "movzbq %1, %0\n"
    "done_get:\n"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile (
    "movabsq $done_put, %0\n"
    "movb %b2, %1\n"
    "done_put:\n"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

void halt(void) {
	// 거의 사용하지 않는게 좋음.
	power_off();
}

// exit() -> 실행중인 스레드? 프로세스? 종료 후 status 리턴
void exit(int status) {
	struct thread *cur = thread_current();
	thread_current()->tf.R.rdi = status;
	thread_current()->is_exit = 1;
	thread_current()->exit_status = status; 
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

// fork() ->  💩💩왕중요💩💩
pid_t fork (const char *thread_name) {
	printf("===== FORK RETURNED ======== 	\n");
	return process_fork(thread_name, &thread_current()->tf);
}

// wait() -> 자식 스레드가 일을 마칠때까지 기다림  💩💩왕중요💩💩
int wait (pid_t pid) {
	//  TODO: pid != tid 이슈가 있을 수 있음 
	return process_wait(pid);
}

// create() -> 파일 이름과 크기에 해당하는 파일 생성
bool create(const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

// remove() -> 파일 이에 해당하는 파일 제거
bool remove(const char *file) {
	return filesys_remove(file);
}

/*open file and allocate fd, allocate file to entry*/
int open (const char *file) {
	fd_t fd = allocate_fd();
	struct file* file_obj = filesys_open(file);
	if (file_obj == NULL) {
		return NULL;
	}
	else {
		thread_current()->fd_arr[fd] = file_obj;
		return fd;
	}
}

// filesize() -> fd가 가리키는 열려있는 파일의 사이즈를 리턴
int filesize (int fd) {
	// fd를 통해 파일을 찾는다.
	struct file* file = thread_current()->fd_arr[fd];
	off_t len = file_length(file);
	return len;
}
// read() -> fd가 가르키는 file에서 size 바이트만큼 buffer로 읽음.
int read (int fd, void *buffer, unsigned size) {
	// fd가 0일때 키보드로 부터 읽어옴.
	if (fd == 0) {
		input_getc();
	}
	struct file* file_obj;
	file_obj = thread_current()->fd_arr[fd];
	return file_read(file_obj, buffer, size);
}

int write (int fd, const void *buffer, unsigned size) {
	if (fd == 1) {
		putbuf(buffer, size);
		return size;
	}
	else{
		struct file* file_obj;
		file_obj = thread_current()->fd_arr[fd];
		return file_write(file_obj, buffer, size);
	}
}


// // write() -> buffer의 내용을 size 바이트만큼 fd에 write
// int write (int fd, const void *buffer, unsigned size) {
// 	return file_write(fd, buffer, size);
// }
// // seek() -> 처음부터 센 것을 기준으로, 다음에 읽거나 쓸 바이트를 position으로 변경
// void seek (int fd, unsigned position) {
// 	return file_seek(fd, position);
// }
// // tell() -> 일의 처음부터 센 것을 기준으로, 다음에 읽을 바이트 혹은 fd에 쓸 다음 바이트의 포지션을 리턴
// unsigned tell (int fd) {
// 	return file_tell(fd);
// }

// close() -> fd가 가르키는 파일 닫고, 해당 fd를 fd_arr에서 할당해제
void close (int fd) {
	struct file* file_obj;
	file_obj = thread_current()->fd_arr[fd];
	if (file_obj == NULL) {
		exit(-1);
	}
	file_close(file_obj);
	thread_current()->fd_arr[fd] = NULL;
}
