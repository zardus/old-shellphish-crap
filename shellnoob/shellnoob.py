#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Yanick Fratantonio <yanick@cs.ucsb.edu>'
__description__ = 'Toolkit for developing shellcodes'
__version__ = "1.0"

import os
import sys
import re
import stat
from tempfile import mktemp

shellcode_t = (
""".section .text
    %s
""")

def shell_to_hex(shell):
    obj = shell_to_obj(shell)
    _hex = obj_to_hex(obj)
    return _hex

def hex_to_shell(_hex):
    obj = hex_to_obj(_hex)
    shell = obj_to_shell(obj)
    return shell

def obj_to_hex(obj):

    tmp_obj_fp = mktemp()
    open(tmp_obj_fp, 'wb').write(obj)

    cmd = 'objdump -d %s | tr -s " "' % tmp_obj_fp
    out = os.popen(cmd).read()
    lines = out.split('\n')
    asm_started = False
    _hex = ''
    for line in lines:
        #if '000000' in line and '<.text>:' in line:
        #    asm_started = True
        #    continue
        #if not asm_started: continue

        # asm started
        try:
            m = re.search('[0-9a-f]+:\s+(([0-9a-f]{2} )+)', line)
            _hex += m.group(1).replace(' ','')
        except:
            if line:
                print 'WARNING (obj_to_hex): weird line: %s' % line

    os.unlink(tmp_obj_fp)

    return _hex

def hex_to_obj(_hex):
    if len(_hex) == 0 or len(_hex) % 2 != 0:
        raise Exception('Not valid _hex: %s' % _hex)

    tmp_shell_fp = mktemp()
    tmp_obj_fp = mktemp()

    asm = '.byte '
    for i in xrange(0, len(_hex), 2):
        asm += '0x%s,' % _hex[i:i+2]
    asm = asm.rstrip(',')
    asm += '\n'

    f = open(tmp_shell_fp, 'w')
    f.write(asm)
    f.close()

    cmd = 'as --32 %s -o %s' % (tmp_shell_fp, tmp_obj_fp)
    os.system(cmd)

    obj = open(tmp_obj_fp, 'rb').read()

    os.unlink(tmp_shell_fp)
    os.unlink(tmp_obj_fp)

    return obj

def hex_to_exe(_hex):
    obj = hex_to_obj(_hex)
    exe = obj_to_exe(obj)
    return exe

def bin_to_hex(_bin):
    return _bin.encode('hex')

def hex_to_bin(_hex):
    return _hex.decode('hex')

def hex_to_c(_hex):
    template = 'char shellcode[] = "%s"'
    content = ''
    for idx in range(0, len(_hex), 2):
        content += '\\x%s' % _hex[idx:idx+2]
    out = template % content
    return out

def hex_to_python(_hex):
    template = '%s'
    content = ''
    for idx in range(0, len(_hex), 2):
        content += '\\x%s' % _hex[idx:idx+2]
    out = template % content
    return out

def hex_to_bash(_hex):
    return hex_to_python(_hex)

class AreYouFuckingKiddingMeException(Exception):
    pass

def hex_to_ruby(_hex):
    raise AreYouFuckingKiddingMeException()

def hex_to_pretty(_hex):
    tmp_obj_fp, tmp_pretty_fp = mktemp(), mktemp()

    obj = hex_to_obj(_hex)
    open(tmp_obj_fp, 'wb').write(obj)

    cmd = 'objdump -d %s > %s' % (tmp_obj_fp, tmp_pretty_fp)
    os.system(cmd)

    pretty = open(tmp_pretty_fp).read()

    os.unlink(tmp_obj_fp)
    os.unlink(tmp_pretty_fp)

    return pretty


### additional blocks

def shell_to_obj(shell):
    tmp_shell_fp, tmp_obj_fp = mktemp(), mktemp()

    open(tmp_shell_fp, 'wb').write(shell)

    cmd = 'as --32 %s -o %s' % (tmp_shell_fp, tmp_obj_fp)
    os.system(cmd)
    if not os.path.isfile(tmp_obj_fp):
        raise Exception("not valid shellcode")

    obj = open(tmp_obj_fp, 'rb').read()

    os.unlink(tmp_shell_fp)
    os.unlink(tmp_obj_fp)

    return obj

def obj_to_shell(obj):
    tmp_obj_fp = mktemp()

    open(tmp_obj_fp, 'wb').write(obj)

    cmd = 'objdump -d %s | tr -s " "' % tmp_obj_fp
    obj_out = os.popen(cmd).read()
    lines = obj_out.split('\n')
    asm_started = False

    out = '.section .text\n'
    for line in lines:
        if '000000' in line and '<.text>:' in line:
            asm_started = True
            continue
        if not asm_started: continue

        # asm started
        try:
            m = re.search('([0-9a-f]+:\s+([0-9a-f]{2} )+)', line)
            if not m:
                continue
            all_but_not_asm = m.group(1)
            asm = line[len(all_but_not_asm):].strip()
            out += '\t%s\n' % asm
        except Exception as e:
            if line:
                print >>sys.stderr, 'WARNING (obj_to_hex): weird line: %s' % line

    os.unlink(tmp_obj_fp)

    return out

def obj_to_exe(obj):
    tmp_obj_fp, tmp_exe_fp = mktemp(), mktemp()

    open(tmp_obj_fp, 'wb').write(obj)

    # ld -V
    # ld -m elf_i386
    cmd = 'ld %s -o %s' % (tmp_obj_fp, tmp_exe_fp)
    os.system(cmd)

    exe = open(tmp_exe_fp, 'rb').read()

    os.unlink(tmp_obj_fp)
    os.unlink(tmp_exe_fp)

    return exe

### util functions

def create_shellcode(inss, shell_fp):
    out = ''
    for i in inss:
        out += i + '\n'
    shellcode = shellcode_t % out
    open(shell_fp, 'w').write(shellcode)

def ins_to_opcode(ins):
    create_shellcode([ins], '/tmp/shell.s')
    shell = open('/tmp/shell.s', 'rb').read()
    obj = shell_to_obj(shell)
    _hex = obj_to_hex(obj)
    return _hex

def opcode_to_ins(opcode):
    _hex = opcode.replace(' ', '')
    obj = hex_to_obj(_hex)
    shell = obj_to_shell(obj)

    inss = shell.split('\n')
    ins = 'null'
    for _ins in reversed(inss):
        if _ins.strip(' \n\t'):
            ins = _ins.strip()
            break
    return ins

def inss_to_opcodes(inss):
    raise Exception('not implemented')

def opcodes_to_inss(opcodes):
    raise Exception('not implemented')

def run_interactive_mode():
    print 'ins_to_opcode (1) or opcode_to_ins (2)?:',
    answer = raw_input()
    while answer != '1' and answer != '2':
        print 'seriously? dude, choose between 1 and 2:',
        answer = raw_input()
    ins_to_opcode_flag = True if answer == '1' else False
    if ins_to_opcode_flag:
        print 'ins_to_opcode selected'
        ins = ''
        while True:
            while not ins:
                print '>>',
                ins = raw_input()
            try:
                opcode = ins_to_opcode(ins)
                print '%s ~> %s' % (ins, opcode)
            except Exception as e:
                print 'ERROR: %s' % e
            ins = ''
    else:
        print 'opcode_to_ins selected'
        opcode = ''
        while True:
            while not opcode:
                print '>>',
                opcode = raw_input()
            try:
                ins = opcode_to_ins(opcode)
                print '%s ~> %s' % (opcode, ins)
            except Exception as e:
                print 'ERROR: %s' % e
            opcode = ''

def convert(input_fp, output_fp, input_fmt, output_fmt, with_breakpoint):
    # reading the input
    if input_fp == '-':
        _input = sys.stdin.read()
    else:
        _input = open(input_fp, 'rb').read()

    # converting the input to hex
    if input_fmt != 'hex':
        _hex = eval('%s_to_hex' % input_fmt)(_input)
    else:
        _hex = _input.rstrip()

    if with_breakpoint:
        # XXX XXX XXX PLATFORM DEPENDENT!! ATTENTION!!
        _hex = 'cc' + _hex

    # converting hex to the output fmt
    if output_fmt != 'hex':
        _output = eval('hex_to_%s' % output_fmt)(_hex)
    else:
        _output = _hex

    # writing the output
    if output_fp == '-':
        sys.stdout.write(_output)
    else:
        open(output_fp, 'wb').write(_output)

    if output_fmt == 'exe' and output_fp != '-':
        # chmod +x
        os.chmod(output_fp, stat.S_IXUSR)

def print_usage():
    print >>sys.stderr, '%s [--from-INPUT] (input_file_path | - ) [--to-OUTPUT] [output_file_path | - ]' % sys.argv[0]
    print >>sys.stderr, '%s -i (for interactive mode)' % sys.argv[0]
    print >>sys.stderr, '%s -c (insert a breakpoint at the beginning of the shellcode (PLATFORM DEPENDENT!!))' % sys.argv[0]
    print >>sys.stderr, ''
    print >>sys.stderr, 'supported INPUT format: shell, obj, bin, hex'
    print >>sys.stderr, 'supported OUTPUT format: shell, obj, exe, bin, hex, C, python, bash, ruby, pretty'


def main():
    args = sys.argv[1:]

    with_breakpoint = False

    if '-h' in args or len(args) == 0:
        print_usage()
        sys.exit(0)
    elif '-i' in args:
        run_interactive_mode()
        sys.exit(0)
    elif '-t' in args:
        test()
        sys.exit(0)
    elif '-c' in args:
        with_breakpoint = True
        args.remove('-c')

    curr_arg_idx = 0

    # determine the input format
    input_fmt = None
    curr_arg = args[curr_arg_idx]
    if curr_arg.startswith('--from-'):
        input_fmt = curr_arg[len('--from-'):]
        if input_fmt not in ['shell', 'obj', 'bin', 'hex']:
            raise Exception('input format "%s" not supported' % input_fmt)
        curr_arg_idx += 1

    input_fp = args[curr_arg_idx]
    if input_fp != '-':
        input_fp = os.path.join(os.getcwd(), input_fp)
        if not os.path.isfile(input_fp):
            raise Exception('file %s does NOT exist' % input_fp)
    curr_arg_idx += 1

    if not input_fmt:
        # ok, let's guess the input fmt
        dot_idx = input_fp.find('.')
        if dot_idx == -1:
            raise Exception('it was not possible to detect the input format')
        ext = input_fp[input_fp.find('.')+1:]
        if ext in ['s', 'shell']:
            input_fmt = 'shell'
        elif ext in ['o', 'obj']:
            input_fmt = 'obj'
        elif ext in ['bin']:
            input_fmt = 'bin'
        elif ext in ['hex']:
            input_fmt = 'hex'
        else:
            raise Exception('input format "%s" not supported' % input_fmt)

    output_fmt = None
    curr_arg = args[curr_arg_idx]
    if curr_arg.startswith('--to-'):
        output_fmt = curr_arg[len('--to-'):]
        if output_fmt not in ['shell', 'obj', 'exe', 'bin',
                              'hex', 'c', 'python', 'bash',
                              'ruby', 'pretty']:
            raise Exception('output format "%s" not supported' % output_fmt)
        curr_arg_idx += 1

    output_fp = None
    if curr_arg_idx < len(args):
        output_fp = args[curr_arg_idx]
        curr_arg_idx += 1

    if not output_fmt:
        # ok, let's guess the output fmt
        dot_idx = output_fp.find('.')
        if dot_idx == -1:
            raise Exception('it was not possible to detect the output format')
        ext = output_fp[output_fp.find('.')+1:]
        if ext in ['s', 'shell']:
            output_fmt = 'shell'
        elif ext in ['o', 'obj']:
            output_fmt = 'obj'
        elif ext in ['exe']:
            output_fmt = 'exe'
        elif ext in ['bin']:
            output_fmt = 'bin'
        elif ext in ['hex']:
            output_fmt = 'hex'
        elif ext in ['c', 'C']:
            output_fmt = 'c'
        elif ext in ['py', 'python']:
            output_fmt = 'python'
        elif ext in ['sh', 'bash']:
            output_fmt = 'bash'
        elif ext in ['rb', 'ruby']:
            output_fmt = 'ruby'
        elif ext in ['pretty']:
            output_fmt = 'pretty'
        else:
            raise Exception('output format "%s" not supported' % output_fmt)

    if output_fp == '-':
        pass
    elif output_fp != None:
        output_fp = os.path.join(os.getcwd(), output_fp)
    else:
        # choose the output_fp starting from the input_fp and the I/O
        # formats
        input_sfx = '.%s' % input_fmt
        output_sfx = '.%s' % output_fmt
        if input_fp.endswith(input_sfx):
            output_fp = input_fp[:-len(input_sfx)] + output_sfx
        else:
            output_fp = input_fp + output_sfx

    print >>sys.stderr,'output wrote to file:', output_fp

    convert(input_fp, output_fp, input_fmt, output_fmt, with_breakpoint)


if __name__== '__main__':
    main()
