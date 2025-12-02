#include <stdio.h>
#include <string.h>

void parse_input(const char *input) {
    char buffer[16];
    printf("Parsing input...\n");
    strcpy(buffer, input);
    printf("Received: %s\n", buffer);
}

int count_vowels(const char *str) {
    int count = 0;
    for (int i = 0; str[i] != '\0'; i++) {
        char c = str[i];
        if (c=='a'||c=='e'||c=='i'||c=='o'||c=='u' ||
            c=='A'||c=='E'||c=='I'||c=='O'||c=='U') {
            count++;
        }
    }
    return count;
}

#define INPUT_SIZE 1024

int main() {
    char input[INPUT_SIZE];

    printf("=== Simple Text Analyzer ===\n");
    printf("Enter text: ");

    if (fgets(input, INPUT_SIZE, stdin) == NULL) {
        printf("No input provided.\n");
        return 1;
    }

    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
    }

    parse_input(input);

    int vowels = count_vowels(input);
    printf("Vowel count: %d\n", vowels);

    printf("Analysis complete.\n");
    return 0;
}
