#!/usr/bin/env python3
## -*- coding: utf-8 -*-
##
##  Copyright (C) 2012 - Jonathan Salwan - http://twitter.com/JonathanSalwan
## 
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program.  If not, see <http://www.gnu.org/licenses/>.
##


import sys
import http.client
import urllib.parse
import re

class ShellStorm():
    def __init__(self):
        pass

    def searchShellcode(self, keyword):
        try:
            print("Connecting to shell-storm.org...")
            s = http.client.HTTPConnection("shell-storm.org")
            s.request("GET", "/api/?s=" + urllib.parse.quote(str(keyword)))
            res = s.getresponse()
            data = res.read().decode('utf-8')
            data_l = data.split('\n')
        except Exception as e:
            print(f"Cannot connect to shell-storm.org: {e}")
            return None

        data_dl = []
        for data in data_l:
            if not data.strip():
                continue
            try:
                desc = data.split("::::")
                if len(desc) < 5:
                    continue
                    
                try:
                    dico = {
                             'ScAuthor': desc[0],
                             'ScArch': desc[1],
                             'ScTitle': desc[2],
                             'ScId': desc[3],
                             'ScUrl': desc[4],
                             'ScSize': int(''.join(x for x in desc[2][-10:-5] if x.isdigit()))
                           }
                except Exception:
                    dico = {
                             'ScAuthor': desc[0],
                             'ScArch': desc[1],
                             'ScTitle': desc[2],
                             'ScId': desc[3],
                             'ScUrl': desc[4],
                             'ScSize': 0
                           }

                data_dl.append(dico)
            except Exception as e:
                print(f"Error processing entry: {e}")
                continue

        try:
            return sorted(data_dl, key=lambda x: x['ScSize'], reverse=True)
        except Exception as e:
            print(f"Could not sort by size: {e}")

        return data_dl

    def displayShellcode(self, shellcodeId):
        if shellcodeId is None:
            return None

        try:
            print("Connecting to shell-storm.org...")
            s = http.client.HTTPConnection("shell-storm.org")
        except Exception as e:
            print(f"Cannot connect to shell-storm.org: {e}")
            return None

        try:

            s.request("GET", "/shellcode/files/shellcode-" + str(shellcodeId) + ".html")
            res = s.getresponse()
            data = res.read().decode('utf-8')
            
            # Extract shellcode from the HTML page
            shellcode = self.extractShellcodeFromHTML(data)
            
            if not shellcode:
                print("No shellcode found in the page")
                return None
                
            return shellcode
            
        except Exception as e:
            print(f"Failed to download shellcode from shell-storm.org: {e}")
            return None

    def extractShellcodeFromHTML(self, html_content):
        """Extract shellcode from HTML page content"""
        # Method 1: Try to find content between <pre> tags
        pre_pattern = r'<pre[^>]*>(.*?)</pre>'
        pre_matches = re.findall(pre_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        if pre_matches:
            # Clean the extracted content
            clean_content = pre_matches[0]
            clean_content = re.sub(r'<[^>]+>', '', clean_content)  # Remove any remaining HTML tags
            clean_content = clean_content.replace("&quot;", "\"")
            clean_content = clean_content.replace("&amp;", "&")
            clean_content = clean_content.replace("&lt;", "<")
            clean_content = clean_content.replace("&gt;", ">")
            clean_content = clean_content.strip()
            return clean_content
        
        # Method 2: Look for common shellcode patterns in the entire page
        # This is a fallback if <pre> tags are not found
        shellcode_patterns = [
            r'\\x[0-9a-fA-F]{2}',  # \x41\x42 format
            r'0x[0-9a-fA-F]{2}',    # 0x41 format
            r'[0-9a-fA-F]{8}',      # hex dumps
        ]
        
        for pattern in shellcode_patterns:
            matches = re.findall(pattern, html_content)
            if matches:
                # Return the first reasonable match
                return " ".join(matches[:20]) + "..." if len(matches) > 20 else " ".join(matches)
        
        # Method 3: Return raw text content if no specific patterns found
        # Remove all HTML tags and get clean text
        clean_text = re.sub(r'<[^>]+>', '', html_content)
        clean_text = re.sub(r'\s+', ' ', clean_text).strip()
        
        # Return first 500 characters of clean text
        return clean_text[:500] + "..." if len(clean_text) > 500 else clean_text

    @staticmethod
    def version():
        print("shell-storm API - v0.1")
        print("Search and display all shellcodes in shell-storm database")
        print("Jonathan Salwan - @JonathanSalwan - 2012")
        print("http://shell-storm.org")
        return

class Color():
    @staticmethod
    def red(str):
        return "\033[91m" + str + "\033[0m"

    @staticmethod
    def green(str):
        return "\033[92m" + str + "\033[0m"

    @staticmethod
    def yellow(str):
        return "\033[93m" + str + "\033[0m"

    @staticmethod
    def blue(str):
        return "\033[94m" + str + "\033[0m"

def syntax():
    print(f"Syntax:   {sys.argv[0]} <option> <arg>\n")
    print("Options:  -search <keyword>")
    print("          -display <shellcode id>")
    print("          -version")
    sys.exit(-1)

if __name__ == "__main__":

    if len(sys.argv) < 2:
        syntax()

    mod = sys.argv[1]
    if mod != "-search" and mod != "-display" and mod != "-version":
        syntax()

    if mod == "-search":
        if len(sys.argv) < 3:
            syntax()

        api = ShellStorm()
        res_dl = api.searchShellcode(sys.argv[2])
        if not res_dl:
            print("Shellcode not found")
            sys.exit(0)

        print(f"Found {len(res_dl)} shellcodes")
        print(f"{Color.blue('ScId')}\t{Color.blue('Size')} {Color.blue('Title')}")
        for data_d in res_dl:
            if data_d['ScSize'] == 0:
                print(f"[{Color.yellow(data_d['ScId'])}]\tn/a  {data_d['ScArch']} - {data_d['ScTitle']}")
            else:
                print(f"[{Color.yellow(data_d['ScId'])}]\t{str(data_d['ScSize']).ljust(5)} {data_d['ScArch']} - {data_d['ScTitle']}")

    elif mod == "-display":
        if len(sys.argv) < 3:
            syntax()
        res = ShellStorm().displayShellcode(sys.argv[2])
        if not res:
            print("Shellcode id not found")
            sys.exit(0)
        print(f"{Color.blue(res)}")

    elif mod == "-version":
        ShellStorm.version()

    sys.exit(0)