#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

def parse_header(header):
    lines = header.strip().split('\n')
    header = {}
    now = 0
    while now < len(lines):
        line = lines[now].strip()
        key,_,value = line.partition(':')
        value = value.strip()
        if key == 'tags' or key == 'categories':
            value = []
            while now+1 < len(lines) and lines[now+1].strip().startswith('-'):
                value.append(lines[now+1].strip().strip('-').strip())
                now += 1
        header[key] = value
        now += 1
    return header

def change_header(header):
    header["date"] = header["date"][:10]
    header["layout"] = "post"
    return header

def generate_page(header,content):
    page = "---\n"
    for key,value in header.items():
        if key in ("tags","categories"):
            page += "{}:\n".format(key)
            for v in value: page += "  - {}\n".format(v)
        else: page += "{}: {}\n".format(key,value)
    page += "---\n"
    page += content
    return page

filenames = os.listdir()
for filename in filenames:
    if '.py' in filename: continue
    with open(filename) as data:
        content = data.read()
    os.remove(filename)    
    header,_,content = content.strip('---\n').partition('---\n')
    header = parse_header(header)
    filename = "{}-{}".format(header["date"][:10],filename)
    header = change_header(header)
    page = generate_page(header,content)
    #print(page)
    #print(filename)
    with open(filename,'w') as data:
        data.write(page)
