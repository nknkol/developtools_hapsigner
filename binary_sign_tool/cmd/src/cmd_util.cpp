/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <libgen.h>
#include <set>
#include <unistd.h>
#include "cmd_util.h"
#include "params_run_tool.h"
#include "constant.h"
#include "param_constants.h"

namespace OHOS {
namespace SignatureTools {
const std::regex INTEGER_PATTERN = std::regex("\\d{1,10}");

bool CmdUtil::String2Bool(Options* options, const std::string& option)
{
    std::string val = options->GetString(option);
    if (val == "1" || val == "true" || val == "TRUE") {
        (*options)[option] = true;
    } else if (val == "0" || val == "false" || val == "FALSE") {
        (*options)[option] = false;
    } else {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            val + " is not valid value for " + "-" + option);
        return false;
    }
    return true;
}

static bool UpdateParamForVariantCertInt(const ParamsSharedPtr& param)
{
    int defaultValidity = 0;
    Options* options = param->GetOptions();
    if (options->count(Options::VALIDITY)) {
        int validity = 0;
        std::string val = options->GetString(Options::VALIDITY);
        for (char x : val) {
            if (!isdigit(x)) {
                PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid parameter '"
                                    + val + "', You should fill in the numbers");
                return false;
            }
        }
        if (!StringUtils::CheckStringToint(val, validity)) {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid parameter '"
                                + val + "'");
            return false;
        }
        validity *= ONE_DAY_TIME;
        (*options)[Options::VALIDITY] = validity;
    } else if (param->GetMethod() == GENERATE_CA || param->GetMethod() == GENERATE_APP_CERT ||
               param->GetMethod() == GENERATE_PROFILE_CERT) {
        defaultValidity = DEFAULT_VALIDITY_DAYS * ONE_DAY_TIME;
        (*options)[Options::VALIDITY] = defaultValidity;
    } else if (param->GetMethod() == GENERATE_CERT) {
        defaultValidity = DEFAULT_CUSTOM_VALIDITY_DAYS * ONE_DAY_TIME;
        (*options)[Options::VALIDITY] = defaultValidity;
    }
    return true;
}

static bool UpdateParamForVariantInt(const ParamsSharedPtr& param)
{
    Options* options = param->GetOptions();
    // general
    if (options->count(Options::KEY_SIZE)) {
        std::string keySize = options->GetString(Options::KEY_SIZE);
        if (keySize == "NIST-P-256") {
            (*options)[Options::KEY_SIZE] = NIST_P_256;
        } else if (keySize == "NIST-P-384") {
            (*options)[Options::KEY_SIZE] = NIST_P_384;
        } else {
            PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "not supported '" + keySize
                                + "' Key algorithms length");
            return false;
        }
    }
    if (!UpdateParamForVariantCertInt(param)) {
        return false;
    }
    return true;
}

static bool UpdateParamForVariantBoolKeyUsage(const ParamsSharedPtr& param)
{
    Options* options = param->GetOptions();

    // The bool type is used only by the "generate-cert" module
    if (options->count(Options::KEY_USAGE_CRITICAL)) {
        if (!CmdUtil::String2Bool(options, Options::KEY_USAGE_CRITICAL)) {
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::KEY_USAGE_CRITICAL] = DEFAULT_KEY_USAGE_CRITICAL;
    }

    // The bool type is used only by the "generate-cert" module
    if (options->count(Options::EXT_KEY_USAGE_CRITICAL)) {
        if (!CmdUtil::String2Bool(options, Options::EXT_KEY_USAGE_CRITICAL)) {
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::EXT_KEY_USAGE_CRITICAL] = DEFAULT_EXT_KEY_USAGE_CRITICAL;
    }
    return true;
}

static bool UpdateParamForVariantBoolProfileSigned(const ParamsSharedPtr& param)
{
    Options* options = param->GetOptions();

    // The bool type is used only by the "sign-elf" module
    if (options->count(Options::PROFILE_SIGNED)) {
        std::string val = options->GetString(Options::PROFILE_SIGNED);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::PROFILE_SIGNED] = DEFAULT_PROFILE_SIGNED_1;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::PROFILE_SIGNED] = DEFAULT_PROFILE_SIGNED_0;
        } else {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                                val + " is not valid value for "+"-" + Options::PROFILE_SIGNED);
            return false;
        }
    } else if (param->GetMethod() == SIGN_ELF) {
        (*options)[Options::PROFILE_SIGNED] = DEFAULT_PROFILE_SIGNED_1;
    }

    return true;
}

static bool UpdateParamForVariantBoolSelfSign(const ParamsSharedPtr& param)
{
    Options* options = param->GetOptions();
    // The bool type is used only by the "sign-elf" module
    if (options->count(Options::SELF_SIGN)) {
        std::string val = options->GetString(Options::SELF_SIGN);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::SELF_SIGN] = ParamConstants::SELF_SIGN_TYPE_1;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::SELF_SIGN] = ParamConstants::SELF_SIGN_TYPE_0;
        } else {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                                val + " is not valid value for "+"-" + Options::SELF_SIGN);
            return false;
        }
    } else if (param->GetMethod() == SIGN_ELF) {
        (*options)[Options::SELF_SIGN] = ParamConstants::SELF_SIGN_TYPE_0;
    }

    return true;
}

static std::string GetParentPath(const std::string &outFilePath)
{
    if (outFilePath.size() == 0) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            "get_parent_path realpath error, empty input");
        return "";
    }

    if (outFilePath.size() > PATH_MAX) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            "get_parent_path realpath error, input too long");
        return "";
    }

    // Extract the directory part before calling realpath.
    // The output file may not exist yet, so realpath on the full path
    // would fail. We first resolve the parent directory.
    std::string dirPath = outFilePath;
    size_t lastSlash = dirPath.find_last_of('/');
    if (lastSlash != std::string::npos && lastSlash > 0) {
        dirPath = dirPath.substr(0, lastSlash);
    } else {
        dirPath = ".";
    }

    char resolvedPath[PATH_MAX + 1] = {0x00};
    if (realpath(dirPath.c_str(), resolvedPath) == nullptr) {
        SIGNATURE_TOOLS_LOGI("Get realpath from %s may failed (dir does not exist)", dirPath.c_str());
        return "";
    }
    resolvedPath[PATH_MAX] = '\0';
    SIGNATURE_TOOLS_LOGI("GetParentPath, resolvedPath:%s", resolvedPath);
    return std::string(resolvedPath);
}

static std::string GetFileName(const std::string &path)
{
    size_t lastSlash = path.find_last_of('/');
    if (lastSlash == std::string::npos) {
        return path;
    }

    return path.substr(lastSlash + 1);
}

bool CmdUtil::UpdateParamForCheckOutFile(Options* options, const std::initializer_list<std::string>& outFileKeys)
{
    for (auto& key : outFileKeys) {
        if (options->count(key)) {
            std::string outFilePath = options->GetString(key);
            std::string parentPath = GetParentPath(outFilePath);

            // Purpose: To prevent the user output path from passing an empty string. eg "   "
            std::string tmpOutFilePath = outFilePath;
            tmpOutFilePath.erase(std::remove_if(tmpOutFilePath.begin(),
                tmpOutFilePath.end(), ::isspace), tmpOutFilePath.end());

            if (parentPath.empty() && !tmpOutFilePath.empty()) {
                parentPath = "./";
            }
            char realFilePath[PATH_MAX + 1] = {0x00};
            if (parentPath.size() > PATH_MAX) {
                PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "'" + outFilePath + "' File path longer than '"
                                    + std::to_string(PATH_MAX) + "' characters");
                return false;
            }
            if (realpath(parentPath.c_str(), realFilePath) == nullptr) {
                PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "The '" + outFilePath +
                                    "' file does not exist or the path is invalid"
                                    + ", parameter name '-" + key + "'");
                return false;
            }
            std::string charStr(realFilePath);
            std::string fileName = GetFileName(outFilePath);
            if (fileName.empty()) {
                PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "The file name cannot be empty '"
                                    + outFilePath + "', parameter name '-" + key + "'");
                return false;
            } else {
                SIGNATURE_TOOLS_LOGI("UpdateParamForCheckOutFile GetFileName:%s", fileName.c_str());
            }
            (*options)[key] = charStr + "/" + fileName;
        }
    }
    return true;
}

bool CmdUtil::UpdateParamForCheckInFile(Options* options, const std::initializer_list<std::string>& inFileKeys)
{
    for (auto& key : inFileKeys) {
        if (options->count(key)) {
            std::string inFilePath = options->GetString(key);
            char realFilePath[PATH_MAX + 1] = {0x00};
            if (inFilePath.size() > PATH_MAX) {
                PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "'" + inFilePath + "' File path longer than '"
                                    + std::to_string(PATH_MAX) + "' characters");
                return false;
            }
            if (realpath(inFilePath.c_str(), realFilePath) == nullptr) {
                PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "The '" + inFilePath +
                                    "' file does not exist or the path is invalid"
                                    + ", parameter name '-" + key + "'");
                return false;
            }
            std::string charStr(realFilePath);
            (*options)[key] = charStr;

            if (!FileUtils::IsValidFile(inFilePath)) {
                return false;
            }
        }
    }

    return true;
}

static bool UpdateParamForCheckSignAlg(const ParamsSharedPtr& param)
{
    // check signAlg
    Options* options = param->GetOptions();
    if (options->count(Options::SIGN_ALG)) {
        std::string signAlg = options->GetString(Options::SIGN_ALG);
        if (signAlg != SIGN_ALG_SHA256 && signAlg != SIGN_ALG_SHA384) {
            PrintErrorNumberMsg("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR, "'" + signAlg + "' parameter is incorrect");
            return false;
        }
    }
    return true;
}

static bool UpdateParamForOutform(const ParamsSharedPtr& param)
{
    // check generate_app_cert generate_profile_cert
    Options* options = param->GetOptions();
    if (param->GetMethod() == GENERATE_APP_CERT ||
        param->GetMethod() == GENERATE_PROFILE_CERT) {
        if (options->count(Options::OUT_FORM)) {
            std::string outForm = options->GetString(Options::OUT_FORM);
            if (outForm != OUT_FORM_CERT && outForm != OUT_FORM_CERT_CHAIN) {
                PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "parameter '" + outForm
                                    + "' format error, Outform only supprot cert/cerChain");
                return false;
            }
        } else {
            (*options)[Options::OUT_FORM] = OUT_FORM_CERT_CHAIN;
        }
    }
    return true;
}

static bool UpdateParam(const ParamsSharedPtr& param)
{
    if (!UpdateParamForVariantInt(param)) {
        return false;
    }
    if (!UpdateParamForVariantBoolKeyUsage(param)) {
        return false;
    }
    if (!UpdateParamForVariantBoolProfileSigned(param)) {
        return false;
    }
    if (!UpdateParamForVariantBoolSelfSign(param)) {
        return false;
    }
    if (!UpdateParamForCheckSignAlg(param)) {
        return false;
    }
    if (!UpdateParamForOutform(param)) {
        return false;
    }
    return true;
}

int CmdUtil::GetCommandParameterKey(const char strChar, std::string& strChars, std::vector<std::string>& trustList,
                                    std::string& keyStandBy)
{
    if (strChar == '-') {
        bool isTrust = std::find(trustList.begin(), trustList.end(), strChars) != trustList.end();
        if (!isTrust) {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "There is no '"
                                + strChars + "' command for the trust list");
            return RET_FAILED;
        }
        keyStandBy = strChars.substr(1);
    } else {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "'" + strChars
                            + "' Parameters error, Param key - value must in pairs");
        return RET_FAILED;
    }

    return RET_OK;
}

bool CmdUtil::Convert2Params(char** args, const size_t size, const ParamsSharedPtr& param)
{
    param->SetMethod(args[1]);
    std::string keyStandBy = "";
    bool readKey = true;
    std::vector<std::string> trustList = ParamsTrustList::GetInstance().GetTrustList(args[1]);
    if (trustList.empty()) {
        return false;
    }
    std::string strChars;
    for (size_t i = 2; i < size; i++) {
        if (readKey) {
            strChars = args[i];
            if (GetCommandParameterKey(args[i][0], strChars, trustList, keyStandBy) == RET_OK) {
                readKey = false;
            } else {
                return false;
            }
        } else {
            bool success = ValidAndPutParam(param, keyStandBy, args[i]);
            if (success) {
                keyStandBy = "";
                readKey = true;
            } else {
                return false;
            }
        }
    }
    param->GetOptions()->emplace(Options::MODE, LOCAL_SIGN);
    if (!readKey) {
        PrintErrorNumberMsg("INVALIDPARAM_ERROR", INVALIDPARAM_ERROR,
                            "The last value of parameter cannot be omitted");
        return false;
    }
    if (!UpdateParam(param)) {
        return false;
    }
    return true;
}

bool CmdUtil::ValidAndPutParam(const ParamsSharedPtr& params, const std::string& key, char* value)
{
    std::string  str = "Pwd";
    bool result = true;
    if (key.empty()) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            "The command-line parameter key cannot be empty");
        result = false;
    } else if (strlen(value) == 0) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            "The command-line parameter value cannot be empty");
        result = false;
    } else if (params->GetOptions()->count(key)) {
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR,
                            "Duplicate command parameter are not allowed '" + key + "'");
        result = false;
    } else if (key.length() >= str.length() && key.substr(key.length() - INVALIDCHAR) == str) {
        params->GetOptions()->emplace(key, value);
    } else {
        if (key == Options::KEY_ALIAS || key == Options::ISSUER_KEY_ALIAS) {
            std::string keyAlias = value;
            std::transform(keyAlias.begin(), keyAlias.end(), keyAlias.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            params->GetOptions()->emplace(key, keyAlias);
        } else {
            params->GetOptions()->emplace(key, std::string(value));
        }
    }
    return result;
}

bool CmdUtil::JudgeSignAlgType(const std::string& signAlg)
{
    if (signAlg != SIGN_ALG_SHA256 && signAlg != SIGN_ALG_SHA384) {
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "not supported '" + signAlg + "' signature algorithm");
        return  false;
    }
    return true;
}
} // namespace SignatureTools
} // namespace OHOS
