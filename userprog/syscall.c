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
	printf("===entered syscall_handler that we made===\n");
	
	// TODO: Your implementation goes here.
	// 유저 스택에 저장되어 있는 시스템 콜 넘버를 이용해 시스템 콜 핸들러 구현
	// 스택 포인터가 유저 영역인지 확인
	check_address(f->rsp);
	printf("===address check passed!!=== \n", f->R.rax);
	printf("===this is my system call<<< %d >>>>=== \n", f->R.rax);
	switch (f->R.rax) {
		case SYS_HALT:
			halt();
			break;
		
		case SYS_WRITE:
			printf("===we came in to write we made !===\n");
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
	}

	printf ("system call!\n");
	thread_exit ();
}

// TBD chobae : pintos syscall func add
void check_address(void *addr)	{
	/*  포인터가 가리키는 주소가 유저영역의 주소인지 확인
		잘못된 접근일 경우 프로세스 종료
		유효한 주소 (0x8048000 ~ 0x0000000)인지 확인
	*/
	if (is_kernel_vaddr(addr)) {
		process_exit();
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