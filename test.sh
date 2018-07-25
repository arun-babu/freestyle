rm -rf test 2>/dev/null
rm -rf freestyle.o 2>/dev/null

gcc -c freestyle.c

LFLAGS=""
OS=`uname`

if [ $OS == "Linux" ]
then 
	LFLAGS="-lbsd"	
fi

gcc -o test test.c freestyle.o $LFLAGS 

./test
