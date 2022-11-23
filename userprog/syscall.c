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
#include "threads/init.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
syscall_handler (struct intr_frame *f UNUSED) {
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
		// case SYS_FORK:
		// 	fork();
		// 	break;
		// case SYS_EXEC:
		// 	exec(f->R.rdi);
		// 	break;
		// case SYS_WAIT:
		// 	wait();
		// 	break;
		case SYS_CREATE:
			// printf("==== f->R.rdi = %s\n", f->R.rdi);
			// printf("==== f->R.rsi = %d\n", f->R.rsi);
			// printf("==== f->R.rdx = %d\n", f->R.rdx);
			// check_address(f->R.rdi);
			if (f->R.rdi == NULL) {
				exit(-1);
			}
			else if ( is_kernel_vaddr(f->R.rdi))
			{
				exit(-1);
			}
			
			else {
				f->R.rax = create(f->R.rdi, f->R.rsi) ? 1 : 0;
			}
			break;
		// case SYS_REMOVE:
		// 	remove();
		// 	break;
		// case SYS_OPEN:
		// 	open();
		// 	break;
		case SYS_FILESIZE:
			// filesize();
			break;
		// case SYS_READ:
		// 	read();
		// 	break;
		// case SYS_SEEK:
		// 	seek();
		// 	break;
		// case SYS_TELL:
		// 	tell();
		// 	break;
		// case SYS_CLOSE:
		// 	close();
		// 	break;
		default:
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

void halt(void) {
	// 거의 사용하지 않는게 좋음.
	power_off();
}

int write (int fd, const void *buffer, unsigned size) {
	if (fd == 1) {
		putbuf(buffer, size);
		return size;
	}
	
	// return file_write(fd, buffer, size);
}

// exit() -> 실행중인 스레드? 프로세스? 종료 후 status 리턴
void exit(int status) {
	struct thread *cur = thread_current();
	thread_current()->tf.R.rdi = status;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

// create() -> 파일 이름과 크기에 해당하는 파일 생성
bool create(const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

// filesize() -> fd가 가리키는 열려있는 파일의 사이즈를 리턴
int filesize (int fd) {
	return file_length(fd);
}