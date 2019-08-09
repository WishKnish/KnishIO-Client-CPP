#pragma once

#include <exception>
#include <iostream>
#include <string>

class AtomsNotFoundException : public std::exception
{
public:
	AtomsNotFoundException() : std::exception("The molecule does not contain atoms") {}
	AtomsNotFoundException(const char *msg) : std::exception(msg) {}
};
