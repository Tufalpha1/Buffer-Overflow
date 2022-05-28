###BUFFER OVERFLOW MANUAL




Stack Buffer Overflow Theory
Stack buffer overflow is a memory corruption vulnerability that occurs when a program writes more data to a buffer located on the stack than what is actually allocated for that buffer, therefore overflowing to a memory address that is outside of the intended data structure.
This will often cause the program to crash, and if certain conditions are met, it could allow an attacker to gain remote control of the machine with privileges as high as the user running the program, by redirecting the flow execution of the application to malicious code.
Before diving into an actual attack, it is crucial to understand basic concepts of C programming such as memory, the stack, CPU registers, pointers and what happens behind the scenes, in order to take advantage of a memory corruption to compromise a system.




Normally, a process is allocated a certain amount of memory which contains all of the necessary information it requires to run, such as the code itself and any DLLs, which isn’t shared with other processes.
 
Whenever an executable is run, its code is loaded into memory so that it can perform all the tasks that is has been programmed to do, because all of the instructions are loaded onto the program’s memory, this can be changed thus making the application perform unintended actions.
All variables in memory are stored using either little endian (for intel x86 processors) or big endian (for PowerPC) format.
In little endian, the bytes are stored in reverse order. So for example:

•	0x032CFBE8 will be stored as “E8FB2C03”
•	0x7734BC0D will be stored as “0DBC3477”
•	0x0BADF00D will be stored as “0DF0AD0B”

This will come useful when redirecting the application execution as the JMP ESP instruction address will have to be stored in reverse in the exploit.

The Stack
The stack is a section of memory that stores temporary data, that is executed when a function is called.
The stack always grows downwards towards lower values as new information is added to it. The ESP CPU register points to the lowest part of the stack and anything below it is free memory that can be overwritten, which is why it is often exploited by injecting malicious code into it.

CPU Registers
Registers are CPU variables that sore single records, there are a fixed number of registers that are used for different purposes and they all have a specific location in the CPU.
Registers can hold pointers which point to memory addresses containing certain instructions for the program to perform, this can be exploited by using a jump instruction to move to a different memory location containing malicious code.
Intel assembly has 8 general purpose and 2 special purpose 32-bit register. Different compilers may have different uses for the registers, the ones listed below are used in Microsoft’s compiler:


Register	Type	Purpose
EAX	General Purpose	Stores the return value of a function.
EBX	General Purpose	No specific uses, often set to a commonly used value in a
 
		function	to	speed	up calculations.
ECX	General Purpose	Occasionally used as a function parameter and often used as a loop counter.
EDX	General Purpose	Occasionally used as a function parameter, also used for storing short-term variables in a function.
ESI	General Purpose	Used as a pointer, points to the source of instructions that require a source and destination.
EDI	General Purpose	Often used as a pointer. Points to the destination of instructions that require a source and destination.
EBP	General Purpose	Has two uses depending on compile settings, it is either the frame pointer or a general purpose register for storing of data used in calculations
ESP	General Purpose	A special register that stores a pointer to the top of the stack (virtually under the end of the stack).
EIP	Special purpose	Stores a pointer to the address of the instruction that the program is currently executing.
After each instruction, a value equal to the its size is added to EIP, meaning it points at the machine code for the next instruction.
FLAGS	Special purpose	Stores meta-information about the results of previous operations i.e. whether it overflowed the register or whether the operands were equal.
 


Pointers
A pointer is, a variable that stores a memory address as its value, which will correspond to a certain instruction the program will have to perform. The value of the memory address can be obtained by “dereferencing” the pointer.
They are used in buffer overflow attacks to redirect the execution flow to malicious code through a pointer that points at a JMP instruction.

Common Instructions
This section covers some of the most common assembly instructions , their purpose in a program and some example uses:

Instruction type	Description	Example instructions
Pointers and Dereferencing	Since registers simply store values, they may or may not be used as pointers, depending on on the information stored.
If being used as a pointer, registers can be dereferenced, retrieving the value stored at the address being pointed to.	Movq,movb
Doing nothing	The NOP instruction, short for “no operation”, simply does nothing.	NOP
Moving data around	Used to move values and pointers.	Mov,movsx,movzx,lea
Math and logic	Used for math and logic. Some are simple arithmetic operations and some are complex calculations.	Add,sub,inc,dec,and
Jumping around	
Used mainly to perform jumps to certain memory locations , it stores the address to jump to.	Jmp,call,ret,cmp,test
 
Manipulating the stack	Used for adding and removing data from the stack.	Push,pop,pushaw

Some of these instructions are used during the practical example in order to gain remote access to the victim machine.



Stack Buffer Overflow Process
Although applications require a custom exploit to be crafted in order to gain remote access, most stack buffer overflow exploitation, at a high level, involve the following phases:





The next section will cover these phases in great detail, from both a theoretical and practical standpoint.
 
Practical Example
This practical example will demonstrate how to exploit a stack buffer overflow vulnerability that affected FreeFloat FTP Server 1.0, an FTP server application. According to the exploit’s author, the crash occurs when sending the following information to the server:

•	USER + [arbitrary username]
•	PASS + [arbitrary password]
•	REST (used to restart a file transfer from a specified point) + 300+ bytes

The entire exploitation process will be conducted using Immunity Debugger, which is free.
Windows Defender may need to be disabled if using an external host to debug the application, as by default it does not allow incoming connections.

Crashing the application
First of all we have to cause the application to crash, in order to ascertain there is a buffer overflow vulnerability and this can be further exploited to gain remote access.
Once the FreeFloat FTP Server executable has been downloaded, it can be run by double- clicking it:
This will start the FTP server and open port 21 for incoming connections.
Starting the Immunity Debugger, selecting the File → Attach option to attach it to the FreeFloat FTP process:

 
Once the debugger has been attached to the process, it will enter a pause state. In order to start its execution, the Debug → Run option can be used:



Immunity Debugger uses the following panes used to display information:

•	Top-Left Pane – It contains the instruction offset, the original application code, its assembly instruction and comments added by the debugger.
•	Bottom-Left Pane -It contains the hex dump of the application itself.
•	Top-Right Pane – It contains the CPU registers and their current value.
•	Bottom-Right Pane – It contains the Memory stack contents.

Python can be used to generate a buffer of 300 A characters to test the crash. Establishing a TCP connecting with port 21 using Netcat, logging in with test/test and sending REST plus the buffer created using Python to cause the crash:


This has crashed the program and Immunity Debugger has reported an access violation error:
 

 


The EIP register was overwritten with the 300 x41 (which corresponds to A in ASCII) sent through Netcat:

Since EIP stores the next instruction to be executed by the application and we established we can manipulate its value, this can be exploited by redirecting the flow of the program execution to ESP, which can be injected with malicious code.
The fuzzing process can also automated through the use of a Python fuzzer, by sending incremental amounts of data in order to identify exactly at which point the application will crash and therefore stop responding.
 
Identifying the EIP offset
The next step required is to identify which part of the buffer that is being sent is landing in the EIP register, in order to then modify it to control the execution flow of the program. Because all that was sent was a bunch of As, at the moment there is no way to know what part has overwritten EIP.
The Metasploit msf-pattern_create tool can be used to create a randomly generated string that will be replacing the A characters in order to identify which part lands in EIP. Creating a pattern of 300 characters using msf-pattern_create to keep the same buffer length:

Adding the pattern to the buffer variable in the script, instead of sending the “A” characters:

 
Restarting the application, re-attaching Immunity Debugger and running the script:

The randomly generated pattern was sent instead of the A characters.
The application crashed with an access violation error as expected, but this time, the EIP
register was overwritten with “41326941”.

The Metasploit msf-pattern_offset tool can then be used to find the EIP value in the pattern created earlier to calculate the exact EIP offset i.e. the exact location of EIP, which in this case is at byte 246.


Modifying the script to override EIP with four “B” characters instead of the As in order to
verify whether the last test was successful:
 
 


Restarting the application, re-attaching Immunity Debugger and running the script:

As expected, the EIP registry was overwritten with the four “B” characters:
 
 

Now that we have full control over EIP, it can be exploited to change redirect the application execution to certain instructions.

Finding Available Shellcode Space
The purpose of this step is to find a suitable location in the memory for our shellcode to then redirect the program execution to it.
When the last script was executed, the C characters that were used to keep the buffer size as 300 overflowed into ESP, so this could be a good place to insert the shellcode:

We can tell the C characters sent to the application landed in ESP from the fifth one onward
because ESP’s address is 0064FBE8, which corresponds to the second group of Cs.
 
 
We now have to verify whether there is enough space for the shellcode inside ESP, which is what will be executed by the system by the program in order to gain remote access.
A normal reverse shell payload is normally about 300-400 bytes, and because only 50 Cs were sent we cannot tell whether there is enough space for it in ESP.
Modifying the script, adding about 550 C characters to the script in a new shellcode variable:


shellcode = "C" * (800 - (len(offset) -len(EIP))) #Shellcode placeholder using about 550 Cs


Restarting the application, re-attaching Immunity Debugger and running the script:



All the “C” characters that were sent by the script have overwritten ESP:
 
 

To calculate how many C characters made it into ESP, all we need to do is subtract the address where ESP starts to the one where the Cs end.
Beginning of ESP:

 
End of the Cs:

Calculating the difference between the two memory addresses using Python, all of the C characters made it into ESP which makes it a suitable shellcode location.


What if there isn’t enough space?
If there isn’t enough space in the ESP register to insert our shellcode, this can be circumvented by using a first stage payload. Since we should be able to override at least the first few characters of ESP, this will be enough to instruct it to jump to a different register where the shellcode will be placed.
If a different register points to the beginner of the buffer, for example ECX:



Then the opcode used to perform a JMP ECX instruction can be generated:

 
And added to the script, in order to instruct ESP to jump to ECX:

offset = "A" * 246 #defining the offset value

EIP = "B" * 4 #EIP placeholder

first_stage = "\xff\xe1" #defining first stage payload as the JMP ECX instruction shellcode = "C" * (800 - (len(offset) -len(EIP))) #Shellcode placeholder using about 550 Cs

In this scenario, the shellcode is added to the beginning of the buffer, since the register where it is placed is the first one that our data is written to.
So basically this is what happens when the exploit is run:

1.	The shellcode is written to ECX
2.	The buffer causes the application to crash
3.	EIP is overwritten with a JMP ESP instruction which redirects the execution flow to ESP
4.	ESP performs a JMP ECX instruction, redirecting the execution to ECX
5.	The shellcode stored in ECX is then executed

Testing for Bad Characters
Some programs will often consider certain characters as “bad”, and all that means is that if they come across one of them, this will cause a corruption of the rest of the data contained in the instruction sent to the application, not allowing the program to properly interpret the it. One character that is pretty much always considered bad is x00, as it is a null-byte and terminates the rest of the application code.
In this phase all we have to do is identify whether there are any bad characters, so that we can later on remove them from the shellcode.
 
Modifying the script, adding all possible characters in hex format to a badchars variable and sending it instead of the shellcode placeholder:


Restarting the application, re-attaching Immunity Debugger and running the script:
 
 

Right-clicking on the ESP value and selecting “Follow in Dump” to follow ESP in the application
dump and see if all the characters sent made it there:


It looks like the characters stop displaying properly after x09, so this indicates that the next character (x0A) is a bad character
 
 

After removing x0A from the badchars variable and following the same process again, this time the characters stopped after x0C , so x0D is also bad

This time, all of the characters made it into the ESP dump, starting from x01 all the way to xFF, so the only bad characters are x00, x0A and x0D.
 
 

Finding a JMP ESP Return Address
Now that we can control EIP and found a suitable location for our shellcode (ESP), we need to redirect the execution flow of the program to ESP, so that it will execute the shellcode. In order to do this, we need to find a valid JMP ESP instruction address, which would allow us to “jump” to ESP.
For the address to be valid, it must not be compiled with ASLR support and it cannot contain any of the bad characters found above, as the program needs to be able to interpret the address to perform the jump.
Restarting the application, re-attaching Immunity Debugger and using !mona modules command to find a valid DLL/module:

 
Finding a valid opcode for the JMP ESP instruction – FFE4 is what we require:


Using the Mona find command to with to find valid pointers for the JMP ESP instruction:


It looks like a valid pointer was found (0x77EFCE33), and it doesn’t contains any of the bad
characters.

Copying the address and searching for it in the application instructions using the “follow expression” Immunity feature to ensure it is valid:


It looks like it does correspond to a valid JMP ESP instruction address:
 
 

Changing the script replacing the “B” characters used for the EIP register with the newly found
JMP ESP instruction address.
The EIP return address has to be entered the other way around as explained in the memory section, since little endian stores bytes in memory in reverse order.

 
Breakpoints are used to stop the application execution when a certain memory location is reached and they can be used to ensure the JMP ESP instruction is working correctly.
Restarting the application, re-attaching Immunity Debugger and adding a breakpoint on the JMP ESP instruction address by hitting F2, then starting the program execution.
A breakpoint can also be added by right-clicking the memory location in the top-left pane, and selecting the Breakpoint → Memory, on access option:

Executing the script again.
When the application reaches the JMP ESP instruction, which is where the breakpoint was added, the program execution stops as instructed:
When single-stepping into the application execution using F7, this takes us to the C characters which are the placeholder for our shellcode.
 
 

Generating and Adding Shellcode
At this point we can completely control the execution flow of the program, so all that is left to do is add our shellcode to the exploit to trigger a reverse shell.
The shellcode can be generated using MSFvenom with the following flags:

•	-p to specify the payload type, in this case the Windows reverse TCP shell
•	LHOST to specify the local host IP address to connect to
•	LPORT to specify the local port to connect to
•	-f to specify the format, in this case Python
•	-b to specify the bad characters, in this case \x00, \x0A and \x0D
•	-e to specify the encoder, in this case shikata_ga_nai
•	-v to specify the name of the variable used for the shellcode, in this case simply “shellcode”
 
 

Because the shellcode is generated using an encoder (which purpose is basic antivirus evasion), the program first needs to decode the shellcode before it can be run. This process will corrupt the next few bytes of information contained in the shellcode, and therefore a few NOP Slides are required to give the decoder enough time to decode it before it is executed by the program.
NOP Slides (No Operation Instructions) have a value of 0x90 and are used to pass execution to
the next instruction i.e. let CPU “slide” through them until the shellcode is reached.
Adding the shellcode to the script, along with 20 NOP slides at the beginning of it to avoid errors during the decoding phase:
 
 

 
Gaining Remote Access
Once the final exploit has been assembled, the next step is to set up a Netcat listener, which will catch our reverse shell when it is executed, using the following flags:

•	-l to listen for incoming connections
•	-v for verbose output
•	-n to skip the DNS lookup
•	-p to specify the port to listen on


Running the final Python exploit:

 
A call back was received and a reverse shell was granted as the “alpha” user. The privileges
granted by the exploit will always match the ones of the user owning the process.




Conclusion
Stack Buffer Overflow is one of the oldest and most common vulnerabilities exploited by attackers to gain unauthorized access to vulnerable systems.
Control-flow integrity schemes should be implemented to prevent redirection to arbitrary code, prevent execution of malicious code from the stack and randomize the memory space layout to make it harder for attackers to find valid instruction addresses to jump to certain sectors of the memory that may contain executable malicious code.






THIS IS HOW BUFFER OVERFLOW IS DEMONSTRATED.
