#!/usr/bin/python
# password cracker

import argparse
# import bcrypt
import hashlib
from passlib.hash import md5_crypt
import crypt
# import re
import random
import time


USERS = []
FILE = ''
max_num_tries = 999
DICTIONARY = "Dictionary"


def get_user_hash(user_name, FILE):
    try:
        with open(FILE, 'r') as shadow_file:
            list_of_users = shadow_file.readlines()
            for line in list_of_users:
                if user_name in line:
                    print(line)
                    split_line_to_list = line.split(":")
                    pass_hash = split_line_to_list[1]
                    # print(pass_hash, type(pass_hash))
                    return pass_hash
    except:
        print("Incorrect file.")


def create_salt():

    salt_options_list = []
    salt_options_str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for x in salt_options_str:
        salt_options_list.append(x)
    # print(salt)

    # Generate a salt for a SHA1 algorithm
    SHA2_salt = ""          # 16 character salt
    # for i in range(15):
    #     next = random.choice(salt_options_list)
    #     SHA1_salt  next
    SHA1_salt_list = random.choices(salt_options_list, k=8)
    # Generate a salt for a SHA1 algorithm
    SHA2_salt_list = random.choices(salt_options_list, k=16)
    for x in SHA2_salt_list:
        SHA2_salt.join(x)

    return SHA2_salt


def hash_passwords_from_dictionary(orig_hash):

    try:
        num_tries = 1
        with open(DICTIONARY, 'r') as dictionary:
            for word in dictionary.readlines():
                line = word.strip('\n')
                # print(line)

                if num_tries == 100:
                    print("Resetting number of tries for the next word.")
                    num_tries = 1
                elif num_tries > 1 < 100:
                    pass
                else:

                    while num_tries <= max_num_tries:
                        start_time = time.time()
                        salt = orig_hash[3:11]
                        md5_hash_password_using_crypt = crypt.crypt(line, crypt.METHOD_MD5)
                        md5_hash_password_using_hashlib = hashlib.md5(b'123456').hexdigest()
                        md5_hash_password_using_passlib = md5_crypt.hash(line)
                        # sha1_hash_password = crypt.crypt(line, "$6$" + sha1_salt)
                        # sha2_salt = crypt.mksalt(method=crypt.METHOD_SHA512, rounds=None)
                        # sha2_hash_password = crypt.crypt(line, salt=sha2_salt)
                        num_tries += 1
                        # if sha2_hash_password == orig_hash:
                        #     print(orig_hash)
                        #     print("We have a match!!!")
                        #     break
                        if md5_hash_password_using_crypt[3:] == orig_hash[3:]:
                            print("The hashing algorithm used is MD5")
                            print("The original hash is: {0}".format(orig_hash[3:]))
                            print("We have a match!!! Using crypt...")
                            print("It took {0} tries to match the password".format(num_tries))
                            print("The password is: {0}".format(line))
                            print("It took {0} seconds long to crack".format(time.time() - start_time))

                            break
                        elif md5_hash_password_using_hashlib == orig_hash[3:]:
                            print("The hashing algorithm used is MD5")
                            print("The original hash is: {0}".format(orig_hash[3:]))
                            print("We have a match!!! Using Hashlib password".format(num_tries))
                            print("The password is: {0}".format(line))
                            print("It took {0} seconds long to crack".format(time.time() - start_time))
                            break
                        elif md5_hash_password_using_passlib == orig_hash[3:]:
                            print("The hashing algorithm used is MD5")
                            print("The original hash is: {0}".format(orig_hash[3:]))
                            print("We have a match!!! Using Passlib...")
                            print("It took {0} tries to match the password".format(num_tries))
                            print("The password is: {0}".format(line))
                            print("It took {0} seconds long to crack".format(time.time() - start_time))
                            break
                        else:
                            # print(sha2_hash_password)
                            # print("The original hash is: {0}".format(orig_hash[3:]))
                            # print(md5_hash_password_using_hashlib[3:])
                            # print(md5_hash_password_using_crypt[3:])
                            # print(md5_hash_password_using_passlib[3:])
                            print("Trying {0}: Could not find a match. Moving on...".format(num_tries))

    except:
        print("An error occurred")


if __name__ == "__main__":

    # Create a command line parser
    parser = argparse.ArgumentParser()

    # Arguments: ./server.py -d <DIRECTORY> -p <PORT>
    parser.add_argument("-f", "--file", help="The file containing hashed passwords. EX. /etc/shadow", required=True)
    parser.add_argument("-u", "--username", help="user to attack", nargs="*", required=True)

    # Execute the parse_args() method
    args = parser.parse_args()
    FILE = args.file
    for user in args.username:
        USERS.append(user)
        # print(user)

    #print(args.file)

    for user in USERS:
        orig_hash = get_user_hash(user, FILE)
        # sha2_salt = create_salt()
        hash_passwords_from_dictionary(orig_hash)
