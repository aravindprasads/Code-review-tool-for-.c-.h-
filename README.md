# Code-review-tool-for-.c-.h-

A Code Review tool for .C and .H files
--------------------------------------

-> No Compilations needed

-> Integrated with Git Database

-> Can be used as a self-review tool 

-> Captures errors missed by Cppcheck and other similar tools

-> Errors captured here are mostly the ones missed by developers

-> Developed using Python




Usage:
------

1) Copy the code_review.py and config.xml in your working directory

2) To Run => python code_review.py config.xml  [git | all | file <file-name>]

       git -   Take the files that are categorized by "Modified" and "newly created" in git database (Git status command)
       all -  All the ".c" & ".h" files from the working directory
       file <file-name> - Single specific file

3) Errors are captured in a newly created file - "error_file" in same folder where command was executed.

4) Indented files are generated with _new extension during the execution of the tool

   You can delete the generated files (if not interested) using:

       find . -name "*.*_new" -delete


Sample Errors and Warnings captured:
------------------------------------

-> Capture Dangling Pointers

-> Header Gaurds unused in Header files

-> File sizes exceeding 1000 lines

-> Use of  “ ” instead of <> for standard headers

-> Use of strcpy, strcmp, sprintf instead of strncpy, strncmp, snprintf respectively

-> Avoid Global Variables across C files

-> Avoid extern declarations for functions in C files

-> Use of “#if 0” in production code

-> NULL check before free not required

-> Use of goto statements

-> Avoid Magic Numbers

-> Avoiding generic types like ulong, uchar. Instead recommended using uint64_t, uint8_t

-> Inline function exceeding more than 5 lines

-> NULL pointer is not assigned after free

-> Switch case blocks containing more lines thereby affecting readability

-> Use of Asserts at non-critical places in code

-> Avoid usage of Explicit Boolean value comparisons. Use (x) instead of (x == true)

-> Use of 'true‘, ‘false’ instead of 'TRUE', 'FALSE'

-> Use of printf

