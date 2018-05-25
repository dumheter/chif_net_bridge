default:
	gcc -std=c11 -Wall -Wextra -Wpedantic -g -pthread bridge.c -o bridge -Iargparse -Largparse -largparse

run:
	./bridge.exe

clean:
	rm bridge.exe
