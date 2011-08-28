redo-ifchange $1.c
gcc -std=c99 -o $3 -c $1.c -O2 -Wall -Wextra -Werror -Winline -funroll-loops
