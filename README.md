# Rainbow_Table_Cracker
This is a class project where we created a program to take a file full of passwords and create a rainbow table using POSIX threads to increase performance. Finally, the rainbow table is used to crack a text file with users and passwords.
The pr4_p.c file contains the code for the multithreaded program, while the pr4.c has a single-threaded program. 
# Usage
In the terminal run: make clean all, then make test. Make test will run the rainbow table against 1000 passwords and crack all the passwords that were ingested into the rainbow table. 
