//
// Created by Dusan Klinec on 18.06.15.
//

#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <iomanip>
#include "PK_Decryptor_EME_Remote.h"
#include "ShsmUtils.h"

int PK_Decryptor_EME_Remote::decryptCall(const Botan::byte byte[], size_t t) {
    // Generate JSON request for decryption.
    std::string json = ShsmUtils::getRequestDecrypt(this->privKey, byte, t, "nonce");

    // Connect to a remote SHSM socket.
    int sockfd = ShsmUtils::connectSocket(this->connectionConfig);
    if (sockfd < 0){
        DEBUG_MSG("decryptCall", "Socket could not be opened");
        return -1;
    }

    // Send request over the socket.
    int res = ShsmUtils::writeToSocket(sockfd, json);
    if (res < 0){
        DEBUG_MSG("decryptCall", "Socket could not be used for writing");
        return -2;
    }

    // Read JSON response from HSMS.
    std::string response = ShsmUtils::readStringFromSocket(sockfd);

    // Closing opened socket. Refactor for performance.
    close(sockfd);

    // TODO: parse response, extract result, return it.
    Json::Value root;   // 'root' will contain the root value after parsing.
    Json::Reader reader;
    bool parsedSuccess = reader.parse(response, root, false);
    if(!parsedSuccess) {
        DEBUG_MSG("decryptCall", "Could not read data from socket");
        return 1;
    }

    // Let's extract the array contained
    // in the root object
    const Json::Value array = root["array"];

    // Iterate over sequence elements and
    // print its values
    for(unsigned int index=0; index<array.size(); ++index)
    {
        cout<<"Element "
        <<index
        <<" in array: "
        <<array[index].asString()
        <<endl;
    }

    // Lets extract the not array element
    // contained in the root object and
    // print its value
    const Json::Value notAnArray = root["not an array"];

    if(not notAnArray.isNull())
    {
        cout<<"Not an array: "
        <<notAnArray.asString()
        <<endl;
    }

    // If we want to print JSON is as easy as doing:
    cout<<"Json Example pretty print: "
    <<endl<<root.toStyledString()
    <<endl;

    return 0;
}

Botan::SecureVector<Botan::byte> PK_Decryptor_EME_Remote::dec(const Botan::byte byte[], size_t t) const {
    // TODO: implement this decryption stuff...
    return Botan::SecureVector<Botan::byte>(0);
}
