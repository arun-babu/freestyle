CC="gcc -O3 -Wall -Wextra "

rm -rf h
rm -rf freestyle.o 2>/dev/null

$CC -c  freestyle.c

LFLAGS=""
OS=`uname`

if [ $OS == "Linux" ]
then 
	LFLAGS="-lbsd"	
fi

$CC -o h freestyle-password-hash.c freestyle.o $LFLAGS

time ./h
