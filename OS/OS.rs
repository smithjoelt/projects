// myos/src/kernel.rs
#![no_std]
#![no_main]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;
use x86_64::structures::paging::{
    FrameAllocator, MapperAllSizes, Page, PageTable, PageTableFlags, Size4KiB,
};
use x86_64::VirtAddr;

// Global allocator for heap memory
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// Constants for memory layout
const KERNEL_HEAP_START: usize = 0x_0010_0000;
const KERNEL_HEAP_SIZE: usize = 0x_0010_0000;

// Process control block (PCB) structure
struct ProcessControlBlock {
    id: usize,
    entry_point: fn(),
    stack_top: VirtAddr,
}

// System call types
enum SysCall {
    PrintMessage(String),
    Yield,
    Exit,
    SendMessage(usize, String),
    ReceiveMessage(Box<String>),
    // Add more system call types as needed
}

// Message structure for inter-process communication
struct Message {
    sender_id: usize,
    content: String,
}

// Function to handle system calls
fn handle_syscall(
    syscall: SysCall,
    current_process_id: usize,
    processes: &mut Vec<ProcessControlBlock>,
    message_boxes: &mut Vec<Message>,
) {
    match syscall {
        SysCall::PrintMessage(message) => {
            print_message(&message);
        }
        SysCall::Yield => {
            schedule(processes);
        }
        SysCall::Exit => {
            exit_current_process(current_process_id, processes);
        }
        SysCall::SendMessage(receiver_id, message) => {
            send_message(current_process_id, receiver_id, message, message_boxes);
        }
        SysCall::ReceiveMessage(msg_box) => {
            receive_message(current_process_id, msg_box, message_boxes);
        } // Handle other system call types here
    }
}

// Function to yield control to the scheduler
fn schedule(processes: &mut Vec<ProcessControlBlock>) {
    if let Some(current_process) = processes.pop() {
        // Move the current process to the end of the queue
        processes.push(current_process.clone());
        // Switch to the next process
        interrupt::context_switch(processes.last().unwrap(), &current_process);
    }
}

// Function to exit the current process
fn exit_current_process(current_process_id: usize, processes: &mut Vec<ProcessControlBlock>) {
    // Remove the current process from the list
    processes.retain(|process| process.id != current_process_id);
    // Schedule the next process
    schedule(processes);
}

// Function to send a message to another process
fn send_message(
    sender_id: usize,
    receiver_id: usize,
    message: String,
    message_boxes: &mut Vec<Message>,
) {
    // Create a new message
    let new_message = Message {
        sender_id,
        content: message.clone(),
    };

    // Find the receiver in the list of processes
    if let Some(receiver) = message_boxes
        .iter_mut()
        .find(|msg| msg.sender_id == receiver_id)
    {
        // Simulate sending a message by updating the receiver's state
        *receiver = new_message;
    } else {
        // Receiver not found, handle the error
        log_error(&format!(
            "Receiver process with ID {} not found",
            receiver_id
        ));
    }
}

// Function to receive a message from another process
fn receive_message(
    current_process_id: usize,
    msg_box: Box<String>,
    message_boxes: &mut Vec<Message>,
) {
    // Find the message in the list of messages
    if let Some(message) = message_boxes
        .iter()
        .find(|msg| msg.sender_id == current_process_id)
    {
        // Move the content of the message into the provided message box
        *msg_box = Box::new(message.content.clone());
        // Remove the received message from the list
        message_boxes.retain(|msg| msg.sender_id != current_process_id);
    } else {
        // No message found, handle the error
        log_error(&format!(
            "No message found for process with ID {}",
            current_process_id
        ));
    }
}

// Function to initialize the entire kernel securely
fn initialize_secure_kernel(
    boot_info: &'static BootInfo,
) -> (Vec<ProcessControlBlock>, Vec<Message>) {
    // Securely initialize memory and bootloader integration
    let mut processes = initialize_secure_memory_from_bootloader(boot_info);
    let mut message_boxes: Vec<Message> = Vec::new();

    // Securely initialize other kernel components...
    initialize_system_calls();
    initialize_user_processes(&mut processes);

    (processes, message_boxes)
}

// Function to initialize system calls
fn initialize_system_calls() {
    // Set up handlers for system calls
    interrupt::register_syscall_handler(handle_syscall);
}

// Function to initialize user processes
fn initialize_user_processes(processes: &mut Vec<ProcessControlBlock>) {
    // Create two simple user processes
    let _process1 = create_user_process(1, user_process_1, processes);
    let _process2 = create_user_process(2, user_process_2, processes);
}

// Function to create a user process
fn create_user_process(
    id: usize,
    entry_point: fn(),
    processes: &mut Vec<ProcessControlBlock>,
) -> ProcessControlBlock {
    // Allocate stack memory for the process
    let stack_top = ALLOCATOR.lock().allocate_stack();
    let process = ProcessControlBlock {
        id,
        entry_point,
        stack_top,
    };
    processes.push(process.clone());
    process
}

// System call: Print a message
fn syscall_print(message: &String) {
    print_message(message);
}

// System call: Yield to the scheduler
fn syscall_yield(processes: &mut Vec<ProcessControlBlock>) {
    schedule(processes);
}

// System call: Exit the current process
fn syscall_exit(process_id: usize, processes: &mut Vec<ProcessControlBlock>) {
    exit_current_process(process_id, processes);
}

// System call: Send a message to another process
fn yscall_send_message(
    sender_id: usize,
    receiver_id: usize,
    message: String,
    message_boxes: &mut Vec<Message>,
) {
    send_message(sender_id, receiver_id, message, message_boxes);
}

// System call: Receive a message from another process
fn syscall_receive_message(
    current_process_id: usize,
    msg_box: Box<String>,
    message_boxes: &mut Vec<Message>,
) {
    receive_message(current_process_id, msg_box, message_boxes);
}

// Function to initialize secure memory from bootloader information
fn initialize_secure_memory_from_bootloader(
    boot_info: &'static BootInfo,
) -> Vec<ProcessControlBlock> {
    // Extract information from the bootloader
    let memory_map = &boot_info.memory_map;
    let kernel_start = VirtAddr::new(boot_info.physical_memory_offset);

    // Set up a recursive page table mapping the kernel's physical memory to virtual memory
    let mut recursive_page_table =
        unsafe { RecursivePageTable::new(PageTable::new(), kernel_start) };
    setup_page_tables(memory_map, &mut recursive_page_table);

    // Initialize heap memory
    init_heap();

    // Initialize other memory-related features...

    // Create an initial process (kernel process)
    let kernel_process = ProcessControlBlock {
        id: 0,
        entry_point: kernel_main,
        stack_top: VirtAddr::zero(), // Placeholder for kernel stack
    };

    vec![kernel_process]
}

// Function to set up page tables based on the memory map
fn setup_page_tables(memory_map: &MemoryMap, page_table: &mut RecursivePageTable) {
    // Placeholder for setting up page tables based on memory map
    // In a real system, this would involve mapping physical memory to virtual memory
    // and handling memory protection features
    // For now, just identity map the entire physical memory
    for region in memory_map.iter() {
        let start_frame = Frame::containing_address(region.range.start);
        let end_frame = Frame::containing_address(region.range.end - 1u64);
        for frame in Frame::range_inclusive(start_frame, end_frame) {
            let virt_addr = page_table.kernel_start + frame.start_address().as_u64();
            let page = Page::containing_address(virt_addr);
            page_table.page_table.map_to(
                page,
                frame,
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                &mut frame_allocator,
            );
        }
    }
}

// Initialize the heap memory
fn init_heap() {
    let heap_start = KERNEL_HEAP_START;
    let heap_size = KERNEL_HEAP_SIZE;

    unsafe {
        ALLOCATOR.lock().init(heap_start, heap_size);
    }
}

// Function to log errors securely
fn log_error(message: &str) {
    // Implement secure logging (e.g., log to a secure storage, if available)
    // For simplicity, print to the VGA buffer in this example
    print_message(&format!("ERROR: {}", message));
}

// Function to print messages securely
fn print_message(message: &String) {
    // Implement secure message printing (e.g., print to a secure console)
    // For simplicity, print to the VGA buffer in this example
}

// Interrupt handling module
mod interrupt {
    use x86_64::instructions::interrupts::without_interrupts;

    pub fn register_syscall_handler(
        handler: fn(SysCall, usize, &mut Vec<ProcessControlBlock>, &mut Vec<Message>),
    ) {
        // Placeholder for registering a system call handler
        // In a real system, this would involve interacting with interrupt controllers
        // For simplicity, use a global static variable to store the handler
        without_interrupts(|| unsafe {
            SYSCALL_HANDLER = Some(handler);
        });
    }

    // Function to handle interrupts (replace with a real implementation)
    pub extern "x86-interrupt" fn handle_interrupt() {
        // Placeholder for interrupt handling
    }

    // Function for context switching during interrupts
    pub fn context_switch(new_process: &ProcessControlBlock, old_process: &ProcessControlBlock) {
        // Placeholder for context switching during interrupts
    }

    // ... (add other interrupt-related functions)
}

// RecursivePageTable implementation
struct RecursivePageTable {
    page_table: PageTable,
    kernel_start: VirtAddr,
}

impl RecursivePageTable {
    fn new(page_table: PageTable, kernel_start: VirtAddr) -> Self {
        RecursivePageTable {
            page_table,
            kernel_start,
        }
    }
}

impl MapperAllSizes for RecursivePageTable {
    fn translate_page(&self, page: Page) -> Option<Frame> {
        // Placeholder for translating virtual to physical addresses
        // In a real system, this would involve looking up page table entries
        Some(Frame::containing_address(page.start_address()))
    }
}

// Global static variable to store the system call handler
static mut SYSCALL_HANDLER: Option<
    fn(SysCall, usize, &mut Vec<ProcessControlBlock>, &mut Vec<Message>),
> = None;

// Frame allocator
struct FrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<Frame<Size4KiB>> {
        // Placeholder for frame allocation
        // In a real system, this would involve allocating frames from available memory
        Some(Frame::containing_address(0x1000))
    }
}

// Main entry point for the operating system
entry_point!(kernel_main);

// Main function for the operating system kernel
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    // Initialize the kernel securely
    let (mut processes, mut message_boxes) = initialize_secure_kernel(boot_info);

    // Initialize the system call handler
    unsafe {
        interrupt::register_syscall_handler(handle_syscall);
    }

    // Start the scheduler and other kernel components
    loop {
        if let Some(handler) = unsafe { SYSCALL_HANDLER } {
            // Placeholder for handling system calls
            handler(SysCall::Yield, 0, &mut processes, &mut message_boxes);
        }
    }
}

// Panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Placeholder for handling panics securely
    log_error(&format!("PANIC: {:?}", info));
    loop {}
}
