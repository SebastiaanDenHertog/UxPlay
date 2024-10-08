#include "AirPlayServer.h"

int main(int argc, char *argv[])
{
    AirPlayServer airplayserver(8080, "JARVIS");
    airplayserver.initialize(argc, argv);
    airplayserver.run(argc, argv);
    return 0;
}