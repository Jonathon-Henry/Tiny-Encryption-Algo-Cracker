import time
import sys

"""
File: Henryj14_AS1.py
Instructor: Dr. ZhongMei Yao
Written by: Jonathon, Henry
Class: CPS472, Spring 2020
"""

#FeistelRound is a testing method for the encryption algorithm
def feistelRound(X: int, K_j: int, K_k: int, delta: int) -> int:
    return mod_add(((X << 4) & 0xffffffff), K_j) ^ mod_add(((X >> 5) & 0xffffffff), K_k) ^ mod_add(X, delta)


def main():
    start_time = time.time()

    #Input validation
    if len(sys.argv) != 2:
        print("Invalid number of arguments. Usage: {:s} /path/to/input/file".format(sys.argv[0]))
    try:
        file_name = sys.argv[1]
        f = open(file_name)
    except OSError:
        print("Cannot open file {:s}".format(file_name))
        exit(1)
    with f:
        #first and second lines of input split into the array [l_0, r_0, l_1, r_1]
        first = ([int(i) for i in f.readline().split()])
        second = ([int(i) for i in f.readline().split()])
        delta = 0x9e3779b9 #delta given in assignment pdf

        #Generates list of 10 additional pairs of plaintext,ciphertext,
        #similar to the variables first and second.
        #Used for checking key pairs
        next_ten = [[int(i) for i in f.readline().split()] for k in range(10)]

        #bruteforce checks every 32 bit key
        for i in range(2 ** 32):
            #Firstkeyguess and secondkeyguess check the value of k_1 based on the current value of k_0 (i)
            #with two different pairs of plaintext + ciphertext
            firstkeyguess = get_key1_guess(first, i, delta)
            secondkeyguess = get_key1_guess(second, i, delta)

            #If the firstkeyguess and secondkeyguess is the same, check 10 additional times

            #If k_1 is the same for the first 12 pairs of plaintext + ciphertext,
            #it is safe to say that the key pair (k_0, k_1) is equal to (i, firstkeyguess)
            if firstkeyguess == secondkeyguess:
                check = True
                #for the next 10 plaintext, ciphertext pairs, if each key_1 doesnt match
                #the key_1 guess, the key is invalid.
                for next_element in next_ten:
                    if get_key1_guess(next_element, i, delta) != firstkeyguess:
                        check = False
                        break
                if check:
                    print("Success!\nKey_0 is {:d}\nKey_1 is {:d}\nRuntime: {:f} seconds.".format(
                    i, firstkeyguess, time.time() - start_time))
                    exit(0)

#Function to find key_1 given a key_0 and delta
def get_key1_guess(input: list, i: int, delta: int) -> int:
    return mod_sub(
    mod_sub(input[3], input[0]) ^ mod_add((input[1] << 4) & 0xffffffff, i) ^ mod_add(input[1], delta),
    (input[1] >> 5) & 0xffffffff)

#Forcing python to treat adding and subtracting like unsigned 32-bit integers
def mod_add(a: int, b: int) -> int:
    return (a+b) & 0xffffffff

def mod_sub(a: int, b: int) -> int:
    return (a-b) & 0xffffffff



if __name__ == '__main__':
    main()
