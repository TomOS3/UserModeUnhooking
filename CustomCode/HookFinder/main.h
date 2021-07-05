#pragma once

void LoadProloguesFromDisk(DllFunctionMap& expectedData);

void LoadInterestingLibraries(std::set<std::string>& dllsToProcess, int& pid);

