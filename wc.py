#!/bin/python
import os
import sys

total = 0

def wc(path):
    for root_path, dirnames, filenames in os.walk(path):
        print filenames
        print dirnames
        for f  in filenames:
            f_path = "%s" % root_path + f
            count = len(open(f_path, 'rU').readlines())
            print count

def wc_dir(path):
    global total
    sum = 0
    for d in os.listdir(path):
        if os.path.isdir(path + "/" + d):
            continue
        else:
            file_path = "%s/%s" % (path, d)
            if os.path.splitext(file_path)[1] in [".c", ".cc", ".h"]:
                count = len(open(file_path, 'rU').readlines())
   #            print count, f_path
                sum += count
    if sum != 0:
        total += sum
        print "sum:%d dir:%s" % (sum, path)
    for d in os.listdir(path):
        if os.path.isdir(path + "/" + d):
            wc_dir(path + "/" + d)

'''
for dir in os.popen("ls"):
    if os.path.isdir(dir):
    print dir
'''

if __name__ == '__main__':
    path = sys.argv[1]
    wc_dir(path)
    print "total num:", total
