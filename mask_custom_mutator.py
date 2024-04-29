#!/usr/bin/env python
# encoding: utf-8
"""
Example Python Module for AFLFuzz
"""
 
import random
import json
import os
import glob
import pyradamsa

filepath = os.path.dirname(os.path.abspath(__file__))
rad = pyradamsa.Radamsa()

def init(seed):
    random.seed(seed)

def deinit():
    pass
 
def read_mask_file():
 
    with open(filepath + "/result/mask.json", 'r') as file:

        content = file.read()

        data = json.loads(content)
    return data
     
def read_corpus_file(filename_prefix: str)-> str:
    

    file_pattern = os.path.join(filepath, filename_prefix + "*")
    matching_files = glob.glob(file_pattern)

    if matching_files:
      file_to_read = matching_files[0]
      
      with open(file_to_read, 'rb') as file:
        file_contents = file.read()

        return file_contents
    else:

        return 0
 
 
def rule(corpus: str,mask: list)-> bytes:
    count = mask.count(0)
    while True:

        fuzzed = rad.fuzz(corpus)
        
        if len(fuzzed) >= len(corpus):#保證變異長度大於原來長度
            break #由於rad.fuzz不能限制最小長度

    element = [chr(char) for char in fuzzed[:len(corpus)]]

    for j, v in enumerate(mask):
        if v == 0:
            try:
                element[j] = chr(corpus[j])
            except:
                print(f'error: {j}')
    res = ''.join(((qq for qq in element)))
    data = bytes(res, encoding="raw_unicode_escape") + fuzzed[len(corpus) - 1:]
    return data



def custom_fuzz2()-> bytearray:
    mask_value=read_mask_file()
    
    size = random.choice(list(mask_value.keys()))
    corpus_file_name=mask_value[size][0]["corpus"]
    mask=mask_value[size][0]["mask"]
    filename_prefix=corpus_file_name[:2]+"e"+corpus_file_name[3:10]
    corpus=read_corpus_file(filename_prefix)
    mutator_out=rule(corpus,mask)
    return bytearray(mutator_out)

def custom_fuzz1(buf: bytearray)-> bytearray:
    fuzzed = rad.fuzz(buf)
    return bytearray(fuzzed)



def fuzz(buf: bytearray, add_buf: bytearray, max_size: int)-> bytearray:

    custom_strategy_choice = filepath + '/strategy_choice.txt'
    with open(custom_strategy_choice, 'r') as file:
        strategy_num = file.read()
    mutator_out = custom_fuzz2() if int(strategy_num) else custom_fuzz1(buf) #修改strategy_choice.txt來調整策略
    return mutator_out


if __name__ == '__main__':
    data = fuzz('','','')
    print(data)