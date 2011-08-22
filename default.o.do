redo-ifchange $1.c
gcc -std=c99 -o $3 -c $1.c -O2 -Wall -Werror -Winline -funroll-loops -march=i686 -mtune=generic -pipe
