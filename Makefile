CC = gcc
CFLAGS = -O3 -Wall
TARGET = sm3_test
OBJ = sm3.o main.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)

sm3.o: sm3.c sm3.h
	$(CC) $(CFLAGS) -c sm3.c

main.o: main.c sm3.h
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f $(OBJ) $(TARGET)