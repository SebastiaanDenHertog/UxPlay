#include "AirPlayServer.h"

int main(int argc, char *argv[])
{
    AirPlayServer server;
    server.initialize(argc, argv);
    server.start(argc, argv);
    return 0;
}