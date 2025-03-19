// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <vector>

inline void SaveBinaryData(const std::string& filename, std::span<uint8_t> data)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file)
    {
        throw std::ios_base::failure("Failed to open file for writing: " + filename);
    }

    // Write the size of the vector first (optional but helpful for loading)
    size_t size = data.size();
    file.write(reinterpret_cast<const char*>(&size), sizeof(size));
    if (!file)
    {
        throw std::ios_base::failure("Failed to write size to file: " + filename);
    }

    // Write the actual data
    file.write(reinterpret_cast<const char*>(data.data()), size);
    if (!file)
    {
        throw std::ios_base::failure("Failed to write data to file: " + filename);
    }
}

inline std::vector<uint8_t> LoadBinaryData(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        throw std::ios_base::failure("Failed to open file for reading: " + filename);
    }

    // Read the size of the vector
    size_t size;
    file.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (!file)
    {
        throw std::ios_base::failure("Failed to read size from file: " + filename);
    }

    // Read the actual data
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    if (!file)
    {
        throw std::ios_base::failure("Failed to read data from file: " + filename);
    }

    return data;
}
