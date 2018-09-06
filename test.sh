CC="gcc -Ofast "

rm -rf test-functionality 2>/dev/null
rm -rf test-timing 2>/dev/null

rm -rf freestyle.o 2>/dev/null

$CC -c -Wall freestyle.c

LFLAGS=""
OS=`uname`

if [ $OS == "Linux" ]
then 
	LFLAGS="-lbsd"	
fi

$CC -Wall -o test-functionality test-functionality.c freestyle.o $LFLAGS
$CC -Wall -o test-timing test-timing.c freestyle.o $LFLAGS

time ./test-functionality
time ./test-timing
