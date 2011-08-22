redo-ifchange $1.c
clang -o $3 $1.c -O2 -Wall -Werror -Winline -funroll-loops -DTEST
