#!/usr/bin/python

import xml.etree.ElementTree as ET
import os
import sys
import re
import subprocess

##Enable/disable debug logs 
dbg_on = False 

#########################################################################################
#####  RETURN ERROR-FILE HANDLE
#########################################################################################
first_write = True
def get_error_file_handle(error_file):
    global first_write
    if first_write == True:
        wf = open(error_file, "w")
        first_write = False
    else:
        wf = open(error_file, "a")
    return wf        

#########################################################################################
#####  RETURN SRC-FILE HANDLE
#########################################################################################
def get_src_file_handle(src_file):
    f = open(src_file, "r")
    return f        

#########################################################################################
#####  INCREMENT GLOBAL ERROR COUNTER
#########################################################################################
err_counter = 0
def increment_error_counter():
    global err_counter
    err_counter = err_counter + 1

#########################################################################################
#####  RETURN GLOBAL ERROR COUNTER
#########################################################################################
def get_global_error_count():
    global err_counter
    return err_counter

#########################################################################################
#####  CHECK IF LINE IS COMMENTED
#########################################################################################
def check_line_commented(line):
    #split the line into words and spaces. "//" to be checked at the start or after words
    regx = re.compile(r'(\s*)(.*)')
    check_regx = re.compile(r'^//')
    found = regx.search(line)
    new_found = check_regx.search(found.group(2))
    if None != new_found:
        if dbg_on == True:
            print "check_line_commented -- comment at " + str(line_no)
        return True
    return False

#########################################################################################
#####  PRINT FILENAME IN ERROR FILE
#########################################################################################
def print_file_name(file_name, error_file):
    wf = get_error_file_handle(error_file)        
    wf.write("\n\t\t\t\t\t\t\t\t\t============"+file_name+"============\n\n")
    wf.close()

#########################################################################################
#####  CHECK IF FILENAME ALREADY PRINTED ELSE PRINT IT
#########################################################################################
name_already_printed = False
def print_file_name_if_not_before(src_file,error_file):
    global name_already_printed
    if name_already_printed == False:
        print_file_name(src_file, error_file)
        name_already_printed = True
        if dbg_on == True:
            print "called for "+src_file

#########################################################################################
#####  GET THE CONTENTS PRESENT INSIDE A BLOCK
#########################################################################################
def get_block_content(src_file, line_to_read, error_file):
    f = get_src_file_handle(src_file)
    open_brace_found = False
    open_brace_count = 0
    line_no = 0
    no_of_lines = 0
    semi_col_count = 0
    lines = f.readlines()
    regx_open  = re.compile(r'\{')
    regx_close = re.compile(r'\}')
    for line in lines:
        line_no = line_no + 1
        if line_no < line_to_read:
            continue
        #### Open brace found
        if None != regx_open.search(line):
            open_brace_count = open_brace_count + 1
        if open_brace_count:
            semi_col_count = line.count(";")
            if semi_col_count:
                no_of_lines = no_of_lines + semi_col_count
            else:
                no_of_lines = no_of_lines + 1
            #### Close brace found
            if None != regx_close.search(line):
                open_brace_count = open_brace_count - 1
                ####Reached end of block
                if open_brace_count == 0:
                    break
    f.close()
    return no_of_lines

#########################################################################################
#### FILE SIZE
#########################################################################################
def count_no_of_lines(src_file, max_file_size, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    if dbg_on == True:
        print "in count_no_of_lines - src_file-"+src_file+"max_file_size-"+\
              max_file_size+"error_file"+error_file
    lines = f.readlines()
    file_size = len(lines)
    max_len = int(max_file_size)
    if file_size > max_len:
        print_file_name_if_not_before(src_file, error_file)
        increment_error_counter()
        wf.write(str(get_global_error_count())+".File-size is %d: maximum allowed lines %d\n"%(file_size,max_len))
    f.close()
    wf.close()
    return

#########################################################################################
#####  SEARCH FOR PRINTF
#########################################################################################
def search_for_printf(src_file, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    lines = f.readlines()
    line_no = 0
    regx = re.compile(r' printf')
    regx_comment_start = re.compile(r'\/\*')
    regx_comment_end = re.compile(r'\*\/')
    comment_end_found = None
    comment_start_found = None
    flag = 1
    for line in lines:
        line_no = line_no + 1
        if  flag == 1:
            comment_start_found =  regx_comment_start.search(line)
        comment_end_found =  regx_comment_end.search(line)
        if None != comment_start_found:
            flag = 0
            if None == comment_end_found:
               continue
        flag = 1

        if check_line_commented(line) == True:
            continue
        printf_found =  regx.search(line)
        if None != printf_found:
            increment_error_counter()
            print_file_name_if_not_before(src_file, error_file)
            wf.write(str(get_global_error_count())+".printf found at line no : %d\n"%line_no)
    f.close()
    wf.close()
    return

#########################################################################################
#####  GAURDS in .H FILE
#########################################################################################
def gaurd_check(src_file, error_file):
    #Check if its a H file
    retval = False
    src_len = len(src_file)
    if src_file[src_len-2:] == ".h":
        retval = True
    if retval == False:
        if dbg_on == True:
            print "in gaurd_check- "+src_file + "Not a H File. Exiting"
        return
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    lines = f.readlines()
    ifndef = re.compile(r'(#ifndef)\s(\S+)')
    define = re.compile(r'(#define)\s(\S+)')

    gaurd_present = False
    ifndef_var = None
    regx_comment_start = re.compile(r'\/\*')
    regx_comment_end = re.compile(r'\*\/')
    comment_end_found = None
    comment_start_found = None
    flag = 1
    for line in lines:
        if  flag == 1:
            comment_start_found =  regx_comment_start.search(line)
        comment_end_found =  regx_comment_end.search(line)
        if None != comment_start_found:
            flag = 0
            if None == comment_end_found:
               continue
        flag = 1

        if check_line_commented(line) == True:
            continue
        #if #ifndef already found
        if ifndef_var != None:
            #is #define used in next line
            define_var = define.search(line)
            if define_var != None and (ifndef_name == define_var.group(2)):
                gaurd_present = True
                break
        else:
            ifndef_var = ifndef.search(line)
            # #ifndef found.
            if None != ifndef_var:
                ifndef_name = ifndef_var.group(2)
    if gaurd_present != True:
        increment_error_counter()
        print_file_name_if_not_before(src_file, error_file)
        wf.write(str(get_global_error_count())+".No Gaurd found in "+src_file+"\n")

    f.close()
    wf.close()
    return

#########################################################################################
#####  CHECK FOR STANDARD HEADER FILES IN WELL-KNOWN STD PATHS
#########################################################################################
def is_header_present(directory,header):
    if os.path.isdir(directory) == True:
        search_str = "find " + directory + " -name "+ header
        call = subprocess.check_output(search_str, shell=True)
        if call.find(header) != -1:
            return True
    return False

def find_header(header):
    dir1 = "/usr/local/include"
    dir2 = "libdir/gcc/target/version/include"
    dir3 = "/usr/target/include"
    dir4 = "/usr/include"

    if is_header_present(dir1, header) == True:
        return True
    elif is_header_present(dir2, header) == True:
        return True
    elif is_header_present(dir3, header) == True:
        return True
    elif is_header_present(dir4, header) == True:
        return True
    else:
        return False

#########################################################################################
#####  <> for STANDARD HEADERS
#########################################################################################
def std_header_check(src_file, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    new_regx = re.compile(r'(#include)(\s+)([\<\"])(\w+.h)([\>\"])')
    lines = f.readlines()
    line_no = 0
    regx_comment_start = re.compile(r'\/\*')
    regx_comment_end = re.compile(r'\*\/')
    comment_end_found = None
    comment_start_found = None
    flag = 1
    for line in lines:
        line_no = line_no + 1
        if  flag == 1:
            comment_start_found =  regx_comment_start.search(line)
        comment_end_found =  regx_comment_end.search(line)
        if None != comment_start_found:
            flag = 0
            if None == comment_end_found:
               continue
        flag = 1

        if check_line_commented(line) == True:
            continue
        found = new_regx.search(line)
        if found != None:
            header = found.group(4)
            is_apos_der = found.group(3)
            apos_regex = re.compile(r'\"')
            if apos_regex.search(is_apos_der) != None:
                if find_header(header) == True:
                     print_file_name_if_not_before(src_file, error_file)
                     increment_error_counter()
                     wf.write(str(get_global_error_count())+".Use <> instead of \"\" for Standard Header "+\
                               header+" at line "+str(line_no)+"\n")
    f.close()
    wf.close()
    return

#########################################################################################
#####   API FOR STRING RELATED CHECKS
#########################################################################################
def search_for_str(src_file, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    lines = f.readlines()
    line_no = 0
    regx_strcpy = re.compile(r' strcpy')
    regx_strcmp = re.compile(r' strcmp')
    regx_sprintf = re.compile(r' sprintf')
    regx_comment_start = re.compile(r'\/\*')
    regx_comment_end = re.compile(r'\*\/')
    comment_end_found = None
    comment_start_found = None
    flag = 1
    for line in lines:
        line_no = line_no + 1
        if  flag == 1:
            comment_start_found =  regx_comment_start.search(line)
        comment_end_found =  regx_comment_end.search(line)
        if None != comment_start_found:
            flag = 0
            if None == comment_end_found:
               continue
        flag = 1

        if check_line_commented(line) == True:
            continue
        found =  regx_strcpy.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".strcpy should not be used , instead use strncpy : %d\n"%line_no)
        found =  regx_strcmp.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".strcmp should not be used , instead use strncmp : %d\n"%line_no)
        found =  regx_sprintf.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".sprintf should not be used , instead use snprintf : %d\n"%line_no)
    f.close()
    wf.close()

#########################################################################################
#####  ASSERT CHECK FUNCTION
#########################################################################################
def search_for_assert(src_file,assert_check,error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    lines = f.readlines()
    line_no = 0
    regx_comment_start = re.compile(r'\/\*')
    regx_comment_end = re.compile(r'\*\/')
    comment_end_found = None
    comment_start_found = None
    flag = 1
    for line in lines:
        line_no = line_no + 1
        if  flag == 1:
            comment_start_found =  regx_comment_start.search(line)
        comment_end_found =  regx_comment_end.search(line)
        if None != comment_start_found:
            flag = 0
            if None == comment_end_found:
               continue
        flag = 1

        if check_line_commented(line) == True:
            continue
        found =  line.find(assert_check);
        if -1 != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Warning :Assert shall be used only for critical errors : %d\n"%line_no)
        found =  line.find('assert');
        if -1 != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Warning :Assert shall be used only for critical errors : %d\n"%line_no)
    f.close()
    wf.close()

#########################################################################################
#####  RELATIVE PATH CHECK FUNCTION
#########################################################################################
def search_for_rel_path(src_file, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    lines = f.readlines()
    line_no = 0
    regx_comment_start = re.compile(r'\/\*')
    regx_comment_end = re.compile(r'\*\/')
    comment_end_found = None
    comment_start_found = None
    flag = 1
    for line in lines:
        line_no = line_no + 1
        if  flag == 1:
            comment_start_found =  regx_comment_start.search(line)
        comment_end_found =  regx_comment_end.search(line)
        if None != comment_start_found:
            flag = 0
            if None == comment_end_found:
               continue
        flag = 1

        if check_line_commented(line) == True:
            continue
        found =  line.find('../');
        if -1 != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Relative path should not be used : %d\n"%line_no)
    f.close()
    wf.close()

#########################################################################################
#####  EXTERN CHECK FUNCTION
#########################################################################################
def search_for_extern(src_file, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    lines = f.readlines()
    line_no = 0
    regx_comment_start = re.compile(r'\/\*')
    regx_comment_end = re.compile(r'\*\/')
    comment_end_found = None
    comment_start_found = None
    flag = 1
    regx = re.compile(r'extern')

    for line in lines:
        line_no = line_no + 1
        if  flag == 1:
            comment_start_found =  regx_comment_start.search(line)
        comment_end_found =  regx_comment_end.search(line)
        if None != comment_start_found:
            flag = 0
            if None == comment_end_found:
               continue
        flag = 1

        if check_line_commented(line) == True:
            continue
        extern_found =  regx.match(line)
        if None != extern_found:
            is_dotc = re.search('\.c', src_file)
            if None != is_dotc :
               print_file_name_if_not_before(src_file, error_file)
               increment_error_counter()
               wf.write(str(get_global_error_count())+".extern should not be used : %d\n"%line_no)
    f.close()
    wf.close()

#########################################################################################
#####  DEAD CODE CHECK FUNCTION
#########################################################################################
def search_for_dead_code(src_file, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    lines = f.readlines()
    line_no = 0
    prev_line = ""
    regx_dead_code = re.compile(r'#if\s+0')
    regx_free = re.compile(r'\s+free\s*\(')
    regx_NULL_check1 = re.compile(r'!=\s*NULL\s*\)')
    regx_NULL_check2 = re.compile(r'NULL\s*!=')
    regx_comment_start = re.compile(r'\/\*')
    regx_comment_end = re.compile(r'\*\/')
    comment_end_found = None
    comment_start_found = None
    flag = 1
    for line in lines:
        line_no = line_no + 1
        if  flag == 1:
            comment_start_found =  regx_comment_start.search(line)
        comment_end_found =  regx_comment_end.search(line)
        if None != comment_start_found:
            flag = 0
            if None == comment_end_found:
               continue
        flag = 1

        if check_line_commented(line) == True:
            continue
        found =  regx_dead_code.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Avoid #if 0  : %d\n"%line_no)
        free_found =  regx_free.search(line)
        NULL1_found =  regx_NULL_check1.search(prev_line)
        NULL2_found =  regx_NULL_check2.search(prev_line)
        if (None != free_found) and ((None != NULL1_found) or (None != NULL2_found)):
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".NULL check before free not required : %d\n"%line_no)
        line = line.strip()
        if (line != "") and (line != "{"):
            prev_line = line;
    f.close()
    wf.close()

#########################################################################################
#####  INVALID DATA CHECK
#########################################################################################
def search_for_invalid_data(src_file, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    src_len = len(src_file)
    lines = f.readlines()
    line_no = 0
    regx_uchar = re.compile(r'uchar\s+')
    regx_ulong = re.compile(r'ulong\s+')
    regx_uint = re.compile(r'uint\s+')
    regx_goto = re.compile(r'\s+goto\s+')
    regx_TRUE = re.compile(r'=\s*TRUE')
    regx_FALSE = re.compile(r'=\s*FALSE')
    regx_OK = re.compile(r'=\s*OK')
    regx_NOK = re.compile(r'=\s*NOK')
    regx_CONST = re.compile(r'=\s*[1-9]+')
    regx_ARR_INDEX = re.compile(r'\[\s*[1-9]+')
    regx_bool1 = re.compile(r'==\s*true\s*')
    regx_bool2 = re.compile(r'!=\s*true\s*')
    regx_bool3 = re.compile(r'\s*true\s*!=')
    regx_bool4 = re.compile(r'\s*true\s*==')
    regx_bool5 = re.compile(r'==\s*false\s*')
    regx_bool6 = re.compile(r'!=\s*false\s*')
    regx_bool7 = re.compile(r'\s*false\s*!=')
    regx_bool8 = re.compile(r'\s*false\s*==')

    regx_comment_start = re.compile(r'\/\*')
    regx_comment_end = re.compile(r'\*\/')
    comment_end_found = None
    comment_start_found = None
    flag = 1

    for line in lines:
        line_no = line_no + 1
        if  flag == 1:
            comment_start_found =  regx_comment_start.search(line)
        comment_end_found =  regx_comment_end.search(line)
        if None != comment_start_found:
            flag = 0
            if None == comment_end_found:
               continue
        flag = 1

        if check_line_commented(line) == True:
            continue

        found =  regx_uchar.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".uchar should not be used, instead use uint8_t : %d\n"%line_no)
        found =  regx_ulong.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".ulong should not be used, instead use uint64_t : %d\n"%line_no)
        found =  regx_uint.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".uint should not be used, instead use uint_t : %d\n"%line_no)
        found =  regx_goto.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".goto statement found at : %d\n"%line_no)
        found =  regx_TRUE.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Use 'true' instead of 'TRUE' : %d\n"%line_no)
        found =  regx_FALSE.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Use 'false' instead of 'FALSE' : %d\n"%line_no)
        found =  regx_OK.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Do not use OK  : %d\n"%line_no)
        found =  regx_NOK.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Do not use NOK  : %d\n"%line_no)
        if src_file[src_len-2:] == ".c":
            found =  regx_CONST.search(line)
            if None != found:
                print_file_name_if_not_before(src_file, error_file)
                increment_error_counter()
                wf.write(str(get_global_error_count())+".No magic number for assignment, use macros  : %d\n"%line_no)
        found =  regx_ARR_INDEX.search(line)
        if None != found:
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Array index has magic number  : %d\n"%line_no)
        bool1_found =  regx_bool1.search(line)
        bool2_found =  regx_bool2.search(line)
        bool3_found =  regx_bool3.search(line)
        bool4_found =  regx_bool4.search(line)
        bool5_found =  regx_bool5.search(line)
        bool6_found =  regx_bool6.search(line)
        bool7_found =  regx_bool7.search(line)
        bool8_found =  regx_bool8.search(line)
        if (None != bool2_found) or (None != bool3_found) or (None != bool6_found) or (None != bool7_found):
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Explicit boolean value comparison not required , use (!x) : %d\n"%line_no)
        if (None != bool1_found) or (None != bool4_found) or (None != bool5_found) or (None != bool8_found):
            print_file_name_if_not_before(src_file, error_file)
            increment_error_counter()
            wf.write(str(get_global_error_count())+".Explicit boolean value comparison not required , use (x) : %d\n"%line_no)
    f.close()
    wf.close()

#########################################################################################
##### STATIC INLINE RESTRICT TO 5 LINES
#########################################################################################
def search_for_inline(src_file, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    lines = f.readlines()
    line_no = 0
    regx = re.compile(r'\s*static\s*inline ')
    for line in lines:
        line_no = line_no + 1
        inline_found =  regx.match(line)
        if None != inline_found:
            if get_block_content(src_file, line_no, error_file) > 5:
                print_file_name_if_not_before(src_file, error_file)
                increment_error_counter()
                wf.write(str(get_global_error_count())+".Inline function exceeds more than 5 lines : %d\n"%line_no)
    f.close()
    wf.close()

#########################################################################################
##### ASSIGN NULL AFTER FREE
#########################################################################################
def search_for_free_call(src_file, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    lines = f.readlines()
    line_no = 0
    count = 0
    free_regx = re.compile(r'\s*free\s*(.*);')
    null_regx = re.compile(r'\s*=\s*NULL')
    for line in lines:
        line_no = line_no + 1
        pat_found =  free_regx.search(line)
        if None != pat_found:
            count = line_no
            next_line = lines[count]
            while len(next_line.strip()) == 0 :
                count = count + 1
                next_line = lines[count]
            if None == null_regx.search(next_line):
                print_file_name_if_not_before(src_file, error_file)
                increment_error_counter()
                wf.write(str(get_global_error_count())+".NULL pointer is not assigned after free : %d\n"%(line_no))

    f.close()
    wf.close()

#########################################################################################
##### AVOID LONG BLOCKS WITHIN SWITCH CASE STATEMENTS (USE "STATIC INLINE" FUNCTIONS)
#########################################################################################
def avoid_long_blocks_in_switch(src_file, error_file):
    f = get_src_file_handle(src_file)
    wf = get_error_file_handle(error_file)
    lines = f.readlines()
    line_no = 0
    block_count = 0
    switch_regx = re.compile(r'\s*case\s*.*\s*:')
    for line in lines:
        line_no = line_no + 1
        pat_found =  switch_regx.match(line)
        if None != pat_found:
            block_count = get_block_content(src_file, line_no, error_file)
            if block_count > 10:
                print_file_name_if_not_before(src_file, error_file)
                increment_error_counter()
                wf.write(str(get_global_error_count())+".Switch case block found at line no : %d contains %d lines\n"%(line_no, block_count))

    f.close()
    wf.close()

#########################################################################################
#####  READ XML
#########################################################################################
def read_xml(xml_file, input_file, output_file, error_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for child in root.findall('inputs'):
        comment_indentation = child.find('comment-indentation').text
        indent_level = child.find('indent-level').text
        no_tabs = child.find('no-tabs').text
        line_up_parentheses = child.find('line-up-parentheses').text
        blank_lines_after_declarations =child.find('blank-lines-after-declarations').text
        brace_indent = child.find('brace-indent').text
        case_indentation = child.find('case-indentation').text
        blank_lines_after_commas = child.find('blank-lines-after-commas').text
        space_after_function_call_names = child.find('space-after-function-call-names').text
        star_comments = child.find('star-comments').text
        space_after_parentheses = child.find('space-after-parentheses').text
        format_all_comments = child.find('format-all-comments').text
        ignore_newlines = child.find('ignore-newlines').text
        blank_lines_before_block_comments = child.find('blank-lines-before-block-comments').text
        blank_lines_after_procedures = child.find('blank-lines-after-procedures').text
        comment_delimiters_on_blank_lines = child.find('comment-delimiters-on-blank-lines').text
        swallow_optional_blank_lines = child.find('swallow-optional-blank-lines').text
        space_after_cast = child.find('space-after-cast').text
        line_length = child.find('line-length').text
        break_before_boolean_operator = child.find('break-before-boolean-operator').text
        gnu_style = child.find('gnu-style').text
        dont_break_procedure_type = child.find('dont-break-procedure-type').text
        max_file_len = child.find('max-file-len').text
        print_check = child.find('print-check').text
        str_check = child.find('str-check').text
        assert_check = child.find('assert-check').text
        rel_path_check = child.find('rel-path-check').text
        extern_check = child.find('extern-check').text
        dead_code = child.find('dead-code').text
        invalid_data = child.find('invalid-data').text


    command = "indent -i"+indent_level+" -bli"+brace_indent+" -cli"+case_indentation+\
                  " -c"+comment_indentation+" -l"+line_length

    if no_tabs == "true":
        command = command+" --no-tabs"
    if line_up_parentheses == "true":
        command = command+" -lp"
    else:
        command = command+" -nlp"
    if blank_lines_after_declarations == "true":
        command = command+" -bad"
    if blank_lines_after_commas == "true":
        command = command+" -bc"
    else:
        command = command+" -nbc"
    if space_after_function_call_names == "true":
        command = command+" -pcs"
    else:
        command = command+" -npcs"
    if star_comments == "true":
        command = command+" -sc"
    else:
        command = command+" -nsc"
    if space_after_parentheses == "true":
        command = command+" -prs"
    else:
        command = command+" -nprs"
    if format_all_comments == "true":
        command = command+" -fca"
    else:
        command = command+" -nfca"
    if ignore_newlines == "true":
        command = command+" -nhnl"
    else:
        command = command+" -hnl"
    if blank_lines_before_block_comments == "true":
        command = command+" -bbb"
    else:
        command = command+" -nbbb"
    if blank_lines_after_procedures == "true":
        command = command+" -bap"
    else:
        command = command+" -nbap"
    if comment_delimiters_on_blank_lines == "true":
        command = command+" -cdb"
    else:
        command = command+" -ncdb"
    if swallow_optional_blank_lines == "true":
        command = command+" -sob"
    else:
        command = command+" -nsob"
    if space_after_cast == "true":
        command = command+" -cs"
    else:
        command = command+" -ncs"
    if break_before_boolean_operator == "true":
        command = command+" -bbo"
    else:
        command = command+" -nbbo"
    if gnu_style == "true":
        command = command+" -gnu"
    if dont_break_procedure_type == "true":
        command = command+" -npsl"
    else:
        command = command+" -psl"

    if dbg_on == True:
        print "comment_indentation=" + command

    #indent call
    os.system(command+" "+input_file+" -o "+ output_file)

    #File size call
    count_no_of_lines(input_file,max_file_len, error_file)
    #"printf" check call
    if print_check == "YES":
        if dbg_on == True:
            print "calling search_for_printf function"
        search_for_printf(input_file, error_file)
    #Gaurd check call
    gaurd_check(input_file, error_file)
    #Standard Header Check
    std_header_check(input_file, error_file)

    if str_check == "YES":
        if dbg_on == True:
            print "calling search_for_str function"
        search_for_str(input_file, error_file)

    if dbg_on == True:
        print "calling search_for_assert function"
    search_for_assert(input_file, assert_check, error_file)

    if rel_path_check == "YES":
        if dbg_on == True:
            print "calling search_for_rel_path function"
        search_for_rel_path(input_file, error_file)

    if extern_check == "YES":
        if dbg_on == True:
            print "calling search_for_extern function"
        search_for_extern(input_file, error_file)

    if dead_code == "YES":
        if dbg_on == True:
            print "calling search_for_dead_code function"
        search_for_dead_code(input_file, error_file)

    if invalid_data == "YES":
        if dbg_on == True:
            print "calling search_for_invalid_data function"
        search_for_invalid_data (input_file, error_file)

    search_for_inline(input_file, error_file)
    search_for_free_call(input_file, error_file)
    avoid_long_blocks_in_switch(input_file, error_file)

#########################################################################################
#####  MAIN FUNCTION
#########################################################################################
def main():
    arg_count = len(sys.argv)
    if arg_count <= 2:
        print ""
        print "usage : tool <xml-file> [git|all|file <file-name>]"
        print ""
        sys.exit(0)
    xml_file = sys.argv[1]
    if(False == os.path.isfile(xml_file)):
        print ""
        print "File \"",src_file," \"does not exist"
        print ""
        sys.exit(0)

    error_file = "error_file"
    print ""

    if sys.argv[2] == "git":
        try:
            call = subprocess.check_output("git status", shell=True)
            lines = call.splitlines()
            new_regx = re.compile(r'(new file:)(\s+)([\w///.-]+)')
            mod_regex = re.compile(r'(modified:)(\s+)([\w///.-]+)')

            for line in lines:
                new_found = new_regx.search(line)
                if new_found != None:
                    input_file = new_found.group(3)
                    output_file = new_found.group(3)+"_new"
                    print("Checking "+input_file+" .....")
                    read_xml(xml_file, input_file, output_file, error_file)
                else:
                    mod_found = mod_regex.search(line)
                    if mod_found != None:
                       input_file = mod_found.group(3)
                       output_file = mod_found.group(3)+"_new"
                       print("Checking "+input_file+" .....")
                       read_xml(xml_file, input_file, output_file, error_file)

            print "\n#########################################################################################"
            print "Captured coding mistakes count : %d"%get_global_error_count()
            print "Errors captured in File \"error_file\""
            print "Indented files are suffixed with \"_new\"" 
            print "#########################################################################################\n\n"

        except subprocess.CalledProcessError:
            print "\n >>>Error in Git status command"
            print ""

    elif sys.argv[2] == "all":
        command = "find . -name \"*.[ch]\""
        call = subprocess.check_output(command, shell=True)
        lines = call.splitlines()
        new_regx = re.compile(r'([\w///.-]+)')

        for line in lines:
            new_found = new_regx.search(line)
            if new_found != None:
                input_file = new_found.group(0)
                output_file = new_found.group(0)+"_new"
                print("Checking "+input_file+" .....")
                read_xml(xml_file, input_file, output_file, error_file)

        print "\n#########################################################################################"
        print "Possible Errors Count : %d"%get_global_error_count()
        print "Errors captured in File \"error_file\""
        print "Indented files are suffixed with \"_new\"" 
        print "#########################################################################################\n\n"

    elif sys.argv[2] == "file":
        if arg_count <= 3:
            print ""
            print "usage : tool <xml-file> [git|all|file <file-name>]"
            print ""
            sys.exit(0)
        file_name  = sys.argv[3]
        if(False == os.path.isfile(file_name)):
            print ""
            print "File \"",src_file," \"does not exist"
            print ""
            sys.exit(0)
        print("Checking "+file_name+" .....")
        output_file = file_name+"_new"
        read_xml(xml_file, file_name, output_file, error_file)
       
        print "\n#########################################################################################"
        print "Possible Errors Count : %d"%get_global_error_count()
        print "Errors captured in File \"error_file\""
        print "Indented files are suffixed with \"_new\"" 
        print "#########################################################################################\n\n"

    else: 
        print "Invalid option"
        sys.exit(0)

#########################################################################################
##### CHECK IF THIS FILE IS FOR EXECUTION OR OTHER MODULE INCLUSIONS
#########################################################################################
if __name__ == '__main__':
    main()
