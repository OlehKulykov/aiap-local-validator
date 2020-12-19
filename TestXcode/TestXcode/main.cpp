
#include <iostream>

namespace validator {
extern void test(void);
}

int main(int argc, const char * argv[]) {
    validator::test();
    return 0;
}
