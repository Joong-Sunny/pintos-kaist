#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"

#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

#define MAX(a,b) (a > b ? a : b)

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/*TBD sunny: addd BLOCKED LIST and init it*/
static struct list sleep_list;
/*TBD DONE*/

/*TBD chobae: 모든 thread를 관리하는 list*/
static struct list all_list;
/*TBD DONE*/

/* Idle thread. */                       
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/*TBD: sunny 전역변수 선언, sleep list대기중인 녀석들 중 wake_tick최소값*/
static int64_t next_tick_to_awake;
/*TBD done*/

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
/* oh~yes global variable*/

void 
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);
	/*TBD sunny: init sleep_list*/
	list_init (&sleep_list);
	/*TBD sunny done*/

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();

}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	// if (strcmp(name, "child") ==0 ){
	// 	priority =39; //해결사 등장
	// }

	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();
	printf("===name=%s , tid=%d, priority= %d \n", name, tid, priority);	/* Initialize thread. */

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	t->priority = priority;
	t->parent_tid = thread_current()->tid;
	list_push_back(&thread_current()->children, &t->child);

	thread_unblock (t); // readylist <- (t) insert!
	
	struct thread *cur = thread_current();
	

	if (strcmp(name, "child") ==0 ){
		// list_push_back(&ready_list, &(t->elem) ); //해결사 등장
		// tid = 0;
	}
	else{

	if (!list_empty(&ready_list)){
		// if (cur->priority <= t->priority) {
		if (cmp_priority(&(t->elem), &(cur->elem), NULL)){
			thread_yield();
		}
	}

	}
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void

thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	list_insert_ordered (&ready_list, &t->elem, cmp_priority, NULL);
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();
	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	
	process_exit ();
	sema_up(&thread_current()->wait);
	
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	// printf("==current thread after YIELD is.. %s, next_thread_to run is... %s \n", thread_current()->name, next_thread_to_run()->name);

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		list_insert_ordered (&ready_list, &curr->elem, cmp_priority, NULL);
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
	
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {

	thread_current ()-> init_priority = new_priority;
	/*TODO : donation을 고려하여 thread_set_priority() 함수를 수정한다

			refresh_priority() 함수를 사용하여 우선순위 변경으로 인한 donation 관련정보 갱신
			donation_priority(), test_max_priority() 함수를 적절히 사용하여 priority donation을 수행하고 스케줄링한다.
	 
	*/

	refresh_priority();   
	donate_priority();
	test_max_priority();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->init_priority = priority;
	t->magic = THREAD_MAGIC;
	t->wait_on_lock = NULL;
	list_init(&t->donations);
	
	for (int i = 0; i < 128; ++i) {
		t->fd_arr[i] = NULL;
	}
	
	struct file *stdin, *stdout, *stderr;
	t->fd_arr[0] = stdin;
	t->fd_arr[1] = stdout;
	t->fd_arr[2] = stderr;

	sema_init(&t->wait, 0);
	t->parent_tid = 0;
	t->is_exit = 0;
	t->exit_status = 0;
	list_init(&t->children);
}


/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

void thread_sleep(int64_t ticks){
 /* 현재 스레드가 idle 스레드가 아닐경우 (식당이 꽉 찼을 때) thread의 상태를 BLOCKED로 바꾸고 깨어나야 할 ticks을 저장한다.
 -  thread_block함수 호출 (-> 현재 스레드가 THREAD_BLOCK 으로 바뀜)
 -  현재 스레드를 슬립 큐에 삽입한 후에 스케줄한다. 
 -  awake함수가 실행되어야 할 tick값을 update
 - 해당 과정중에는 인터럽트를 받아들이지 않는다. 
 - 함수가 다 실행되면 인터럽트를 받아들인다.
 */
	enum intr_level old_level =intr_disable (); // Disables interrupts and returns the previous interrupt status.
 	struct thread *curr = thread_current ();  //   얘를 블락시키기 -> 깨어나야할 시간(tick)을 저장

	ASSERT(curr != idle_thread);
	update_next_tick_to_awake(curr->wakeup_tick = ticks);    
	list_push_back(&sleep_list, &curr->elem);
	// thread_block();
	do_schedule(THREAD_BLOCKED);
  	intr_set_level(old_level);                 // 기존 인터럽트 레벨을 복구(원래 disabled였을 수도 있어서)

}

/*TBD sunny: wakeup_tick값이 ticks보다 작거나 같은 쓰레드를 깨움
 *현재 대기중인 스레드들의 wakeup_tick변수 중 가장 작은 값을 next_tick_to_awake변수에 저장*/
void thread_awake(int64_t wakeup_tick){
  next_tick_to_awake = INT64_MAX;
  struct list_elem *e;
  e = list_begin(&sleep_list);
  while(e != list_end(&sleep_list)){
    struct thread * t = list_entry(e, struct thread, elem);

    if(wakeup_tick >= t->wakeup_tick){
      e = list_remove(&t->elem);
      thread_unblock(t);
    }else{
      e = list_next(e);
      update_next_tick_to_awake(t->wakeup_tick);
    }
  }
}


void update_next_tick_to_awake(int64_t ticks){
	if (next_tick_to_awake > ticks)
		next_tick_to_awake = ticks;
}

int64_t get_next_tick_to_awake(void){
	return next_tick_to_awake;
	
}
/*TBD sunny done*/


/* TODO : 현재 실행중인 스레드와 가장 높은 우선순위의 스레드의 우선순위를 비교하여 스케줄링*/
void test_max_priority(void){
	// ready_list가 비어있지 않은지 확인

	if(!list_empty(&ready_list)) {
		if (cmp_priority(&(list_entry(list_begin(&ready_list), struct thread, elem)->elem), &(thread_current()->elem), NULL)) {
			/*현재쓰레드.priority <= readylist의 첫번째*/
			thread_yield();
		}
	}
}
/* TODO : 인자로 주어진 스레드들의 우선순위를 비교
   para -> compare thread a, compare thread b
   return -> a > b : 1 , a < b : 0
*/
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)	{
	/*list_insert_ordered에서 사용할 함수. a > b 이면 true 를 리턴해야 한다 */

	struct thread *former = list_entry(a, struct thread, elem);
	struct thread *latter = list_entry(b, struct thread, elem);
	return former->priority > latter->priority;
}

bool cmp_delem_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)	{
	/*list_insert_ordered에서 사용할 함수. a > b 이면 true 를 리턴해야 한다 */

	struct thread *former = list_entry(a, struct thread, donation_elem);
	struct thread *latter = list_entry(b, struct thread, donation_elem);
	return former->priority > latter->priority;
}



/*lock의 홀더에게 donate, 그리고 나를 그들의 Donations에 넣어줌 */ 
void donate_priority(void)	{

	int curr_priority = thread_current()->priority;
	
	/*for the nested loop (줄줄이 사탕으로 전부 끌어올린다) */
	if (thread_current()->wait_on_lock && thread_current()->wait_on_lock->holder) {
		struct thread *twlh = thread_current()->wait_on_lock->holder; //twlh = Target_Wait_on_Lock_Holder
		twlh->priority = curr_priority;
		
		if (twlh) {
			for (int i = 0; i < 8; ++i) {		
				if ( (twlh->wait_on_lock == NULL) || (twlh->wait_on_lock->holder == NULL) )
					// <찐키주인이 기다리는락이 없음>    or   <찐키주인이 기다리는락이 주인없음(였던것..)>
					break;

			twlh->wait_on_lock->holder->priority = curr_priority;
			// list_insert_ordered(&(twlh->wait_on_lock->holder->donations), &(thread_current()->donation_elem), cmp_delem_priority, NULL);
			twlh = twlh->wait_on_lock->holder;
			}
		}	
	}

}

/* 나(current_thread)의 donations에서  내가들고있던 Lock을 원하셨던 분들 제거 */
void remove_with_lock(struct lock *lock)	{

	// coding logic
	// 3-1. current_thread().donation_list를 본다
	struct list_elem *head = list_begin( &(thread_current()->donations) );
	struct thread *curr;
	// 3-2. donation_list에서, 순회를 한다
	while(head != list_end( &(thread_current()->donations) )){
		//3-3. "모~든 리스트"를 순회하며 if (wait_on_lock == lock)을 확인
			//(1) head(elem임)로부터 쓰레드를 찾는다
			curr = list_entry(head, struct thread, donation_elem);
			//(2) 찾은 쓰레드의 wait_on_lock == lock인지 확인한다
			if (curr->wait_on_lock == lock){
				//(3) donations에서 삭제
				list_remove( &(curr->donation_elem) );
			}
		head = head->next;
	}
	// 3-x. (줄어든 donation_list에서, 최대값(priority)를 찾아...) <= 이건 refresh_priority에서 to be continue...
}


/* 도네가 없다면, 본인 pr을, 도네가 있다면 그중 최고로변경!!! */
void refresh_priority(void)	{

	if ( list_empty( &(thread_current()->donations)) ){ 
		/*도네없으면, 본인pr = 본인init */
		thread_current()->priority = thread_current()->init_priority;
	}
	else{
		/*도네있으면, 그중 최고*/
		thread_current()->priority = MAX(
			thread_current()->init_priority,
			list_entry( list_begin(&(thread_current()->donations)), struct thread, donation_elem )->priority // <===이거 init_priority가 되어야하지 않을까??? (sunny추측)
		);
	}
}

// struct thread *
// get_child_process(tid_t child_tid){
// 	struct thread *current = thread_current();
// 	struct list_elem *child_elem = list_begin(&current->children);

// 	//walking
// 	while(child_elem != list_end(&current->children)) {
// 		printf("######\n");
// 		struct thread *child_thread = list_entry(child_elem, struct thread, child);
// 		if(child_thread->tid == child_tid){
// 			return child_thread;
// 		}
// 		child_elem = &list_entry(child_elem->next, struct thread, child)->child;
// 	}
// 	return NULL;
// }

// void remove_child_process(struct thread *c_thread) {
// 	struct thread *current = thread_current();
// 	struct list_elem *child_elem = list_begin(&current->children); //부모가 가지고 있는 children list walking

// 	//walking
// 	while(child_elem != list_end(&current->children)) {
// 		struct thread *child_thread = list_entry(child_elem, struct thread, child);
// 		if(child_thread->tid == c_thread->tid){
// 			list_remove(&child_elem);
// 			return;
// 		}
// 		child_elem = &list_entry(child_elem->next, struct thread, child)->child;
// 	}
// }

struct thread *
find_forked_thread(tid_t parent_tid){

	//1. 레디리스트에서 헤드 찾기
	struct list_elem *e = list_begin(&ready_list);
	//2. walking
	struct thread* t;
	//3. 현재 실행스레드의 자식스레드인지 확인
	while(e != list_end(&ready_list)){
		t = list_entry(e, struct thread, elem);
		// printf("자식 찾았다! 부모 tid=%d, 찾은 자식=%d\n", t->parent_tid, t->tid);
		if(t->parent_tid == parent_tid){
			return t;
		}
		e = e->next;
	}
	return NULL;
}


struct thread *get_child_thread(tid_t child_tid) {
	//1. 현재스레드의 자식리스트에서 헤드 찾기
	struct list_elem *e = list_begin(&thread_current()->children);
	//2. walking
	struct thread* t;
	//3. 인자로 받은 child_tid랑 같은 스레드 있는지 탐색
	while(true){
		t = list_entry(e, struct thread, child);
		if(t->tid == child_tid){
			return t;
		}
		e = e->next;
	}
	return NULL;
}


void push_readylist(struct thread* thread){
	list_push_front(&ready_list, &thread->elem);
}