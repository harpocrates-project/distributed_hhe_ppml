#include <iostream>
#include <string>
#include <curl/curl.h>
#include "hhe.pb.h"

// Function to write the response data to a string
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int main() {
    // Take a string as input
    std::string filename;
    std::cout << "Enter filename: ";
    std::getline(std::cin, filename);

    // Create a DataFile protobuf message
    hheproto::DataFile dataFile;
    dataFile.set_filename(filename);

    // Serialize the message to a string
    std::string serializedData;
    if (!dataFile.SerializeToString(&serializedData)) {
        std::cerr << "Failed to serialize DataFile protobuf message" << std::endl;
        return 1;
    }

    // Initialize CURL
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        // Set the URL for the POST request
        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8080");

        // Set the POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, serializedData.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, serializedData.size());

        // Set the content type to application/octet-stream
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Set the write callback function to capture the response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        std::cout << "Sending data to server" << std::endl;
        // Perform the request
        res = curl_easy_perform(curl);
        std::cout << "Data sent to server" << std::endl;

        // Check for errors
        if(res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        } else {
            // Deserialize the protobuf response
            hheproto::DataFile response;
            if (response.ParseFromString(readBuffer)) {
                // Print the response message
                std::cout << "Received filename: " << response.filename() << std::endl;
            } else {
                std::cerr << "Failed to parse protobuf message." << std::endl;
            }
        }

        // Clean up
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    return 0;
}