gcc -c freestyle.c

LFLAGS=""
OS=`uname`

if [ $OS == "Linux" ]
then 
	LFLAGS="-lbsd"	
fi

gcc -o test test.c freestyle.o $LFLAGS 

./test
