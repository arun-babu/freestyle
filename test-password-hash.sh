CC="gcc -O3 -Wall -Wextra "

rm -rf test-password-hash
rm -rf freestyle.o 2>/dev/null

$CC -c  freestyle.c
$CC -c  freestyle-password-hash.c

LFLAGS=""
OS=`uname`

if [ $OS == "Linux" ]
then 
	LFLAGS="-lbsd"	
fi

$CC -o test-password-hash test-password-hash.c freestyle-password-hash.o freestyle.o $LFLAGS

time ./test-password-hash
