CC="gcc --std=c99 -O3 -Wall -Wextra -Werror -pedantic -pedantic-errors "

rm -rf test-functionality 2>/dev/null
rm -rf test-timing 2>/dev/null
rm -rf test-password-hash 2>/dev/null

rm -rf freestyle.o 2>/dev/null

$CC -c  freestyle.c

LFLAGS=""
OS=`uname`

if [ $OS == "Linux" ]
then 
	LFLAGS="-lbsd"	
fi

$CC -o test-functionality test-functionality.c freestyle.o $LFLAGS
$CC -o test-timing test-timing.c freestyle.o $LFLAGS
$CC -o test-password-hash test-password-hash.c freestyle.o $LFLAGS

time ./test-functionality
time ./test-timing
time ./test-password-hash
