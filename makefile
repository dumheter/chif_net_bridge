default:
	gcc -std=c11 -Wall -Wextra -Wpedantic bridge.c -o bridge

run:
	./bridge.exe

clean:
	rm bridge.exe
