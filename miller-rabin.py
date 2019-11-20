# Ryan McGrane
# C16419862    DT 228/4
# 08/11/19
# Python program that implements the miler Rabin algorithm to check
# if a certain number is prime or not

import random


# Does modular exponentiation.
# It returns (x^y) % p 
def power(x, y, p):
    # Initialize result
    result = 1

    x = x % p

    while y > 0:

        if y & 1:
            result = (result * x) % p

        y = y >> 1
        x = (x * x) % p

    return result


def millerTest(d, n):
    a = 2 + random.randint(1, n - 4)

    # Find a^d % n
    x = power(a, d, n)

    if x == 1 or x == n - 1:
        return True

    while d != n - 1:
        x = (x * x) % n
        d *= 2

        if x == 1:
            return False
        if x == n - 1:
            return True

            # Return composite
    return False


# It returns true if n
# is probably prime
# It returns false if n is
# composite and
def isPrime(n, k):

    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    d = n - 1
    while d % 2 == 0:
        d //= 2

    for i in range(k):
        if not millerTest(d, n):
            return False

    return True


k = 4

print('\n***** Check a number below 100 to see if it is prime ***** \nPress 1 to enter a number \nPress 2 to exit')
menu_choice = int(input("Enter choice:"))

if menu_choice == 2:
    print("\n\t Thank you for using this service\n")

while menu_choice == 1:

    print('\n***** Check a number to see if it is prime *****')
    n = int(input("Enter number:"))

    if isPrime(n, k):
        print(n, end=" is prime ")
        print('\n--------------------------------------------------------------------'
              '\n You have found your prime number using miller rabin algorithm \n'
              '-------------------------------------------------------------------- \n***GoodBye***')
        menu_choice = 2

    else:
        print(n, end=" is not prime")
