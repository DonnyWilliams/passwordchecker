# Making a program to see if a password has ever been hacked
# python3.9 checkmypass.py [*any password(s)]
# Will return how many times a given password was found.
# The more it's found, the more you should change it if you're using it.
# Existing similar tool at haveibeenpwned.com

# This allows us to manually make a request without using a browser.
import requests
# This is a built-in Python module to run strings through hash functions.
# Allows us to do SHA1 hashing
import hashlib
# This is so we can use argv.
import sys

# URL we're using for this + first five characters of the hashed version of password
# we want to check
# SHA1 hash generator at https://passwordsgenerator.net/sha1-hash-generator/
# If we give the clean password or the full hashed version, we'll get Response [400],
# which we don't want; we want Response [200].
# Important princliple is to trust nobody.
# Giving just part of a hashed password string allows us to not give sensitive info
# to this API.
# Theoretically, our own computers are more secure.
# First five characters will return several hundred passwords.
# It's on us to do the rest on our end (see further down this code).
# Commenting next three lines of code out here bc I'm moving it to the function
# def request_api_data() further down.
# url = "https://api.pwnedpasswords.com/range/" + "CBFDA"
# Res is a variable short for response.
# res = requests.get(url)
# Response [400] usually means something's unauthorized, something's not right with
# the API, etc.
# Response [200] is what we're looking for. That means everything's OK.
# print(res)

# This is to finish checking our exact password, rather than just the first five
# hashed characters.
# This way, we don't give this info to anyone outside of our own computer.


def request_api_data(query_char):
    # Replacing second value of first five hashed characters with query_char
    # variable so it's dynamic.
    # It won't work without that last slash in the API address.
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    # This is instead of print(res).
    # With that, we had to wait to see if it printed Response [400] or [200].
    # With this, it automatically throws an error if it's not what we want to see.
    # .status_code is imported from the requests library.
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, Check the API and try again.')
    return res


# Check password if it exists in API response
def pwned_api_check(password):
    # This is to turn our password into a hashed password.
    # This specific syntax is in the hashlib documentation:
    # https://docs.python.org/3/library/hashlib.html
    # The commented-out print below returns b'[whatever we wrote as our password]'
    # print(password.encode('utf-8'))
    # The commented out print below returns:
    # <sha1 _hashlib.HASH object @ 0x10a1d36d0>
    # print(hashlib.sha1(password.encode('utf-8')))
    # The commented out print below returns:
    # cbfdac6008f9cab4083784cbd1874f76618d2a97 (the hashed version of the password)
    # Adding .upper() bc the API will use all caps.
    # .upper() allows us to match exactly with the API.
    # print(hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    # This is to show when we don't use .encode('utf-8')
    # The commented out print below returns:
    # TypeError: Unicode-objects must be encoded before hashing
    # print(hashlib.sha1(password).hexdigest().upper())
    # .hexdigest() is here to display the hexadecimal version of the hashed password.
    # The hexadecimal version can limit how big the password can get.
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # This is to send the hashed password to the API.
    # This creates two variables: one for the first five characters, and another
    # for the rest.
    # You can use [:5] and [5:] bc [:5] is actually 0-4, so there's no overlap.
    first5_char, tail = sha1password[:5], sha1password[5:]
    # This is to call the function with the first5_char variable and store what it
    # returns as a new variable.
    response = request_api_data(first5_char)
    # This commented out print statement is to see what we're working with.
    # print(first5_char, tail)
    return get_password_leaks_count(response, tail)

# This is to learn more about the data we return.
# Using this as return read_res(response) in the last line of pwned_api_check()
# will return a couple hundred hashed passwords.
# That is what we expected for giving the first five characters of our hashed pwd.
# It'll also show at the end how many times each password has been hacked.
# def read_res(response):
#     print(response.text)

# This will loop through all of the returned responses and check for our password.


def get_password_leaks_count(hashes, hash_to_check):
    # This will split the returned responses at the colon, with the hashed passwords
    # on one side and the number of times they've been hacked on the other.
    # Without the .splitlines() at the end, it'll return each individual character
    # as its own line.
    hashes = (line.split(':') for line in hashes.text.splitlines())
    # print(hashes) returns a generator object:
    # <generator object get_password_leaks_count.<locals>.<genexpr> at 0x10c7c7890>
    # We want to look through that generator object as follows:
    # h is for hash
    # Using two variables bc that's what we have in this function.
    for h, count in hashes:
        # We can print either or both variables here with print(h, count)
        # This is finding our exact password using the tail that we never sent out.
        if h == hash_to_check:
            return count
    return 0


# This is to put this all together, receiving the arguments we've created.
# args is any passwords we give it.
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times. You should probs change your password.')
        else:
            print(f'{password} was not found. Carry on, bub.')
    return 'done.'


# This isn't necessary to make this work, but it helps, bc it'll only run the file
# if it's the main one being inputed from the command line, and not if it's being
# imported.
if __name__ == '__main__':
    # This allows us to give it any number of passwords, bc 1 starts after the
    # script.
    # Wrapping this in sys.exit() isn't necessary for this to work, but it makes
    # sure that the program will exit the system call and bring us back to the
    # command line.
    # Working with passwords, especially, you want to try to wrap up all
    # precautions just in case.
    # This will also lead to the "done." being returned, which isn't printed otherwise.
    # If I chose to use this for real and wanted to keep this this way, I'd probably
    # pick something more professional to return than just "done." -- or even not
    # have it return something at all if I didn't feel I needed something to mark
    # the function as having been run and completed.
    sys.exit(main(sys.argv[1:]))

# One way to make this program more secure is to read the passwords from a text file
# instead of a command line argument, bc typing passwords into the command line in
# Terminal might be saved either in the program or on the computer.
# In a text file, you can write a password and then immediately delete it, and the
# program is just reading the text file, so that's all it saves.
# However, it requires the user to write in a text file AND run this .py file.
# Just typing an argument in a command line at the same time you're running a
# program is simpler.
# What is a way to make this as simple as possible for the user while also keeping
# it as secure as possible?c
# I would say putting this on a webpage, where one field runs the program and another
# is an input box, where the user writes the password into what becomes a text file.
# But that still transmits the password across the internet, which is less secure
# than this current program, which has the password never leaving the machine it's
# run on.
# Encryption (more than hashing) is probably a go-to solution for this.
# You lose the security of it never leaving a single machine, but there's the faith
# that the encryption you're using will be strong enough to keep it safe.
# Is there a better way with less of a trade off?
