// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <iostream>
#include <string>

#include <Windows.h>
#include <netlistmgr.h>

#include <wil/com.h>

int __cdecl wmain(int argc, wchar_t** argv)
try
{
    if (argc != 2)
    {
        std::cout << "Must specity either Public or Private" << std::endl;
        return ERROR_INVALID_PARAMETER;
    }

    const std::wstring param(argv[1]);

    NLM_NETWORK_CATEGORY targetCategory{};
    constexpr auto bIgnoreCase = TRUE;
    const auto privateComparison = CompareStringOrdinal(param.c_str(), -1, L"private", -1, bIgnoreCase);
    THROW_LAST_ERROR_IF(privateComparison == 0);
    if (privateComparison == CSTR_EQUAL)
    {
        targetCategory = NLM_NETWORK_CATEGORY_PRIVATE;
    }
    else
    {
        const auto publicComparison = CompareStringOrdinal(param.c_str(), -1, L"public", -1, bIgnoreCase);
        THROW_LAST_ERROR_IF(publicComparison == 0);
        if (publicComparison == CSTR_EQUAL)
        {
            targetCategory = NLM_NETWORK_CATEGORY_PUBLIC;
        }
        else
        {
            std::cout << "Must specity either Public or Private" << std::endl;
            return ERROR_INVALID_PARAMETER;
        }
    }

    const auto coinit = wil::CoInitializeEx();
    const auto nlmInstance = wil::CoCreateInstance<INetworkListManager>(CLSID_NetworkListManager);
    wil::com_ptr<IEnumNetworks> nlmEnumNetworks;
    THROW_IF_FAILED(nlmInstance->GetNetworks(NLM_ENUM_NETWORK_CONNECTED, &nlmEnumNetworks));

    for (;;)
    {
        ULONG fetched{};
        wil::com_ptr<INetwork> nlmNetworkInstance;
        THROW_IF_FAILED(nlmEnumNetworks->Next(1, &nlmNetworkInstance, &fetched));
        if (fetched == 0)
        {
            break;
        }

        wil::unique_bstr currentName;
        THROW_IF_FAILED(nlmNetworkInstance->GetName(currentName.addressof()));
        wil::unique_bstr currentDescription;
        THROW_IF_FAILED(nlmNetworkInstance->GetDescription(currentDescription.addressof()));
        NLM_NETWORK_CATEGORY currentCategory{};
        std::wstring networkString(L"[Name: " + std::wstring(currentName.get()) + L", Description: " + std::wstring(currentDescription.get()) + L"]");

        THROW_IF_FAILED(nlmNetworkInstance->GetCategory(&currentCategory));
        if (currentCategory == NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED)
        {
            std::wcout << L"The Network " << networkString << L" is Domain Authenticated - not updating" << std::endl;
            continue;
        }
        if (currentCategory == targetCategory)
        {
            std::wcout << L"The Network " << networkString << L" is already set to " << param << L" - not updating" << std::endl;
            continue;
        }

        const auto hr = nlmNetworkInstance->SetCategory(targetCategory);
        if (SUCCEEDED(hr))
        {
            std::wcout << "Successfully updated the Category for the Network " << networkString << L" to " << param << std::endl;
        }
        else if (hr == E_ACCESSDENIED)
        {
            std::wcout << L"Failed to update the Network " << networkString << L" : Access Denied (must run as an Administrator)" << std::endl;
        }
        else
        {
            std::wcout << L"Failed to update the Network " << networkString << " : " << std::hex << hr << std::endl;
        }
    }
}
catch (...)
{
    const auto hr = wil::ResultFromCaughtException();
    std::cout << "Failure to instantiate INetworkListManager and find networks: " << std::hex << hr << std::endl;
}
