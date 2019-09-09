CC="clang -Ofast -Wall -Wextra -march=native -pedantic "

rm -rf test-functionality 2>/dev/null
rm -rf test-timing 2>/dev/null
rm -rf test-password-hash 2>/dev/null

rm -rf freestyle.o 2>/dev/null
rm -rf randen-rng/src/randen.o 2>/dev/null

$CC -c freestyle.c

cd randen-rng/src
$CC -c randen.c
cd - >/dev/null


LFLAGS=""
OS=`uname`

if [ $OS == "Linux" ]
then 
	LFLAGS="-lbsd"	
fi

$CC -o test-functionality test-functionality.c freestyle.o randen-rng/src/randen.o $LFLAGS
$CC -o test-timing test-timing.c freestyle.o randen-rng/src/randen.o $LFLAGS
$CC -o test-password-hash test-password-hash.c freestyle.o randen-rng/src/randen.o $LFLAGS

time ./test-functionality
time ./test-timing
time ./test-password-hash
