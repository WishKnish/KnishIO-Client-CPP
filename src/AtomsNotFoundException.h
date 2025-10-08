#pragma once

#include <stdexcept>
#include <iostream>
#include <string>

class AtomsNotFoundException : public std::runtime_error
{
public:
	AtomsNotFoundException() : std::runtime_error("The molecule does not contain atoms") {}
	AtomsNotFoundException(const char *msg) : std::runtime_error(msg) {}
	AtomsNotFoundException(const std::string &msg) : std::runtime_error(msg) {}
};
