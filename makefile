default:
	gcc -std=c11 -Wall -Wextra -Wpedantic -pthread bridge.c -o bridge

run:
	./bridge.exe

clean:
	rm bridge.exe
