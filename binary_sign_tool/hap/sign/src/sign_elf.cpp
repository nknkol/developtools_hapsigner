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

#include "sign_elf.h"
#include <unistd.h>
#include <cstring>
#include <vector>
#include <fstream>
#include <sys/stat.h>

#include "file_utils.h"
#include "string_utils.h"
#include "constant.h"
#include "code_signing.h"
#include "param_constants.h"
#include "profile_sign_tool.h"

namespace OHOS {
namespace SignatureTools {

const std::string SignElf::codesignSec = ".codesign";
const std::string SignElf::profileSec = ".profile";
const std::string SignElf::permissionSec = ".permission";
constexpr size_t MAX_SECTION_SIZE = static_cast<size_t>(0xFFFFFFFF);

bool SignElf::Sign(SignerConfig& signerConfig, std::map<std::string, std::string>& signParams)
{
    std::string inputFile = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);
    ELFIO::elfio elfReader;
    if (!elfReader.load(inputFile)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to load input ELF file");
        return false;
    }
    bool writeProfilFlag = WriteSecDataToFile(elfReader, signerConfig, signParams);
    if (!writeProfilFlag) {
        SIGNATURE_TOOLS_LOGE("[SignElf] WriteSecDataToFile error");
        return false;
    }
    std::string outputFile = signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE);
    std::string tmpOutputFile = outputFile;
    if (outputFile == inputFile) {
        tmpOutputFile = "tmp-signed-elf";
    }
    uint64_t csOffset = 0;
    bool writeCodeSignFlag = WriteCodeSignBlock(elfReader, inputFile, tmpOutputFile, csOffset);
    if  (!writeCodeSignFlag) {
        SIGNATURE_TOOLS_LOGE("[SignElf] WriteCodeSignBlock error");
        return false;
    }
    // cs offset > 0 and 4K alignment
    if (csOffset == 0 || (csOffset % PAGE_SIZE) != 0) {
        SIGNATURE_TOOLS_LOGE("[SignElf] csOffset is not 4K alignment");
        return false;
    }
    std::string selfSign = signParams.at(ParamConstants::PARAM_SELF_SIGN);
    bool generateCodeSignFlag = GenerateCodeSignByte(signerConfig, tmpOutputFile, csOffset, selfSign);
    if  (!generateCodeSignFlag) {
        return false;
    }
    return FileUtils::CopyTmpFileAndDel(tmpOutputFile, outputFile);
}

bool SignElf::loadModule(std::map<std::string, std::string>& signParams, std::string& moduleContent)
{
    if (signParams.find(ParamConstants::PARAM_MODULE_FILE) != signParams.end()) {
        std::string modulefilePath = signParams.at(ParamConstants::PARAM_MODULE_FILE);
        if (FileUtils::ReadFile(modulefilePath, moduleContent) < 0) {
            SIGNATURE_TOOLS_LOGE("[SignElf] Failed to open module file");
            return false;
        }
    } else {
        SIGNATURE_TOOLS_LOGI("[SignElf] No module file");
    }
    if (moduleContent.size() > MAX_SECTION_SIZE) {
        SIGNATURE_TOOLS_LOGE("[SignElf] moduleContent size exceeds maximum allowed section size (4GB)");
        return false;
    }
    return true;
}

bool SignElf::loadProfileAndSign(SignerConfig& signerConfig, std::map<std::string, std::string>& signParams,
                                 std::string& p7b)
{
    std::string profileContent;
    if (signParams.find(ParamConstants::PARAM_BASIC_PROFILE) != signParams.end()) {
        std::string profilefilePath = signParams.at(ParamConstants::PARAM_BASIC_PROFILE);
        if (FileUtils::ReadFile(profilefilePath, profileContent) < 0) {
            SIGNATURE_TOOLS_LOGE("[SignElf] Failed to open profile file");
            return false;
        }
    } else {
        return true;
    }
    std::string profileSigned = signParams.at(ParamConstants::PARAM_BASIC_PROFILE_SIGNED);
    if (profileSigned == DEFAULT_PROFILE_SIGNED_0) {
        std::string alg = signParams.at(ParamConstants::PARAM_BASIC_SIGANTURE_ALG);
        if (ProfileSignTool::SignProfile(profileContent, signerConfig.GetSigner(), alg, p7b) < 0) {
            SIGNATURE_TOOLS_LOGE("[SignElf] SignProfile error");
            return false;
        }
    } else {
        p7b = profileContent;
    }
    if (p7b.size() > MAX_SECTION_SIZE) {
        SIGNATURE_TOOLS_LOGE("[SignElf] profileContent size exceeds maximum allowed section size (4GB)");
        return false;
    }
    return true;
}

bool SignElf::isExecElf(ELFIO::elfio& reader)
{
    ELFIO::Elf64_Half eType = reader.get_type();
    if (eType == ELFIO::ET_EXEC) {
        return true;
    }
    if (eType == ELFIO::ET_DYN && reader.get_entry() > 0) {
        return true;
    }
    return false;
}

bool SignElf::WriteCodeSignBlock(ELFIO::elfio& reader, const std::string& inputFile,
                                   std::string& outputFile, uint64_t& csOffset)
{
    if (reader.sections[codesignSec]) {
        SIGNATURE_TOOLS_LOGE("[SignElf] .codesign section already exists");
        return false;
    }
    return AppendCodeSignSectionPreservingLayout(inputFile, outputFile, csOffset);
}

bool SignElf::WriteSection(ELFIO::elfio& reader, const std::string& content, const std::string& secName)
{
    ELFIO::section* sec = reader.sections[secName];
    if (sec) {
        SIGNATURE_TOOLS_LOGE("[SignElf] %s section already exists", secName.c_str());
        return false;
    }
    sec = reader.sections.add(secName);
    if (!sec) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to create %s section", secName.c_str());
        return false;
    }
    sec->set_type(ELFIO::SHT_PROGBITS);
    sec->set_flags(ELFIO::SHF_ALLOC);
    sec->set_addr_align(1);
    sec->set_data(content);
    return true;
}

bool SignElf::WriteSecDataToFile(ELFIO::elfio& reader, SignerConfig& signerConfig,
                                 std::map<std::string, std::string>& signParams)
{
    if (signParams.at(ParamConstants::PARAM_SELF_SIGN) == ParamConstants::SELF_SIGN_TYPE_1) {
        return true;
    }
    // check elf bin or so
    if (!isExecElf(reader)) {
        return true;
    }
    std::string p7b;
    if (!loadProfileAndSign(signerConfig, signParams, p7b)) {
        return false;
    }
    if (!p7b.empty()) {
        if (WriteSection(reader, p7b, profileSec)) {
            PrintMsg("add profile section success");
        } else {
            return false;
        }
    }
    std::string moduleContent;
    if (!loadModule(signParams, moduleContent)) {
        return false;
    }

    if (!moduleContent.empty()) {
        if (WriteSection(reader, moduleContent, permissionSec)) {
            PrintMsg("add permission section success");
        } else {
            return false;
        }
    }
    return true;
}

bool SignElf::GenerateCodeSignByte(SignerConfig& signerConfig, const std::string& inputFile, uint64_t& csOffset,
                                   const std::string& selfSign)
{
    CodeSigning codeSigning(&signerConfig, (selfSign == ParamConstants::SELF_SIGN_TYPE_1));
    std::vector<int8_t> codesignData;
    bool getElfCodeSignBlockFlag = codeSigning.GetElfCodeSignBlock(inputFile, csOffset, codesignData);
    if (!getElfCodeSignBlockFlag) {
        SIGNATURE_TOOLS_LOGE("[SignElf] get elf code sign block error.");
        return false;
    }
    SIGNATURE_TOOLS_LOGD("[SignElf] elf code sign block off %lu: ,len: %lu .", csOffset, codesignData.size());

    if (codesignData.size() > PAGE_SIZE) {
        SIGNATURE_TOOLS_LOGE("[SignElf] signature size is too large.");
        return false;
    }

    if (!ReplaceDataOffset(inputFile, csOffset, codesignData)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to replace code sign data in file.");
        return false;
    }
    PrintMsg("write code sign data success");
    return true;
}

bool SignElf::ReplaceDataOffset(const std::string& filePath, uint64_t& csOffset, const std::vector<int8_t>& csData)
{
    std::fstream fileStream(filePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!fileStream) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to open file: %s", filePath.c_str());
        return false;
    }

    fileStream.seekp(csOffset, std::ios::beg);
    if (!fileStream) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to seek to offset: %lu", csOffset);
        return false;
    }

    fileStream.write(reinterpret_cast<const char*>(csData.data()), csData.size());
    if (!fileStream) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to write data at offset: %lu", csOffset);
        return false;
    }
    fileStream.flush();
    fileStream.close();
    return true;
}

/*
 * AppendCodeSignSectionPreservingLayout
 *
 * Instead of using ELFIO::save() which re-serializes the entire ELF and can
 * collapse inter-segment padding (breaking p_offset alignment constraints),
 * this function works on raw bytes:
 *
 *   1. Copy the original ELF file byte-for-byte.
 *   2. Parse ELF header and Section Header Table.
 *   3. Append a PAGE_SIZE .codesign placeholder at a page-aligned offset.
 *   4. Build a new shstrtab (old + ".codesign\0").
 *   5. Write a new Section Header Table at the end.
 *   6. Patch e_shoff, e_shnum, e_shstrndx in the ELF header.
 *
 * All original Program Headers, section addresses, offsets, and sizes
 * are preserved exactly.
 */
bool SignElf::AppendCodeSignSectionPreservingLayout(const std::string& inputFile,
                                                     const std::string& outputFile,
                                                     uint64_t& csOffset)
{
    // 1. Read the entire original ELF file
    std::ifstream inFile(inputFile, std::ios::binary | std::ios::ate);
    if (!inFile) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to open input file: %s", inputFile.c_str());
        return false;
    }
    std::streamsize fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);
    if (fileSize <= 0) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Input file empty or unreadable");
        return false;
    }
    std::vector<char> origBytes(static_cast<size_t>(fileSize));
    if (!inFile.read(origBytes.data(), fileSize)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to read input file data");
        return false;
    }
    inFile.close();
    uint64_t origFileSize = static_cast<uint64_t>(fileSize);
    if (origFileSize < 64) { // Minimum ELF64 header size
        SIGNATURE_TOOLS_LOGE("[SignElf] Input file too small to be a valid ELF");
        return false;
    }

    // 2. Parse ELF header (Elf64_Ehdr, 64 bytes)
    // e_shoff: offset 0x28 (8 bytes, uint64_t LE)
    // e_shentsize: offset 0x3A (2 bytes, uint16_t LE)
    // e_shnum: offset 0x3C (2 bytes, uint16_t LE)
    // e_shstrndx: offset 0x3E (2 bytes, uint16_t LE)

    auto readU16 = [](const char* p) -> uint16_t {
        return static_cast<uint16_t>(static_cast<unsigned char>(p[0])) |
               (static_cast<uint16_t>(static_cast<unsigned char>(p[1])) << 8);
    };
    auto readU64 = [](const char* p) -> uint64_t {
        return static_cast<uint64_t>(static_cast<unsigned char>(p[0])) |
               (static_cast<uint64_t>(static_cast<unsigned char>(p[1])) << 8) |
               (static_cast<uint64_t>(static_cast<unsigned char>(p[2])) << 16) |
               (static_cast<uint64_t>(static_cast<unsigned char>(p[3])) << 24) |
               (static_cast<uint64_t>(static_cast<unsigned char>(p[4])) << 32) |
               (static_cast<uint64_t>(static_cast<unsigned char>(p[5])) << 40) |
               (static_cast<uint64_t>(static_cast<unsigned char>(p[6])) << 48) |
               (static_cast<uint64_t>(static_cast<unsigned char>(p[7])) << 56);
    };
    auto writeU16 = [](char* p, uint16_t v) {
        p[0] = static_cast<char>(v & 0xFF);
        p[1] = static_cast<char>((v >> 8) & 0xFF);
    };
    auto writeU32 = [](char* p, uint32_t v) {
        p[0] = static_cast<char>(v & 0xFF);
        p[1] = static_cast<char>((v >> 8) & 0xFF);
        p[2] = static_cast<char>((v >> 16) & 0xFF);
        p[3] = static_cast<char>((v >> 24) & 0xFF);
    };
    auto writeU64 = [](char* p, uint64_t v) {
        p[0] = static_cast<char>(v & 0xFF);
        p[1] = static_cast<char>((v >> 8) & 0xFF);
        p[2] = static_cast<char>((v >> 16) & 0xFF);
        p[3] = static_cast<char>((v >> 24) & 0xFF);
        p[4] = static_cast<char>((v >> 32) & 0xFF);
        p[5] = static_cast<char>((v >> 40) & 0xFF);
        p[6] = static_cast<char>((v >> 48) & 0xFF);
        p[7] = static_cast<char>((v >> 56) & 0xFF);
    };

    char* ehdr = origBytes.data();
    uint64_t e_shoff     = readU64(ehdr + 0x28);
    uint16_t e_shentsize = readU16(ehdr + 0x3A);
    uint16_t e_shnum     = readU16(ehdr + 0x3C);
    uint16_t e_shstrndx  = readU16(ehdr + 0x3E);

    if (e_shentsize < 64 || e_shnum == 0 || e_shstrndx >= e_shnum) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Invalid section header table in ELF");
        return false;
    }

    // 3. Read the shstrtab section header to find its data
    uint64_t shstrtabHdrOff = e_shoff + static_cast<uint64_t>(e_shstrndx) * 64;
    if (shstrtabHdrOff + 64 > origFileSize) {
        SIGNATURE_TOOLS_LOGE("[SignElf] shstrtab header out of file bounds");
        return false;
    }
    char* shstrtabHdr = ehdr + shstrtabHdrOff;
    uint64_t shstrtabOff  = readU64(shstrtabHdr + 0x18); // sh_offset
    uint64_t shstrtabSize = readU64(shstrtabHdr + 0x20); // sh_size

    if (shstrtabOff + shstrtabSize > origFileSize) {
        SIGNATURE_TOOLS_LOGE("[SignElf] shstrtab data out of file bounds");
        return false;
    }

    // 4. Build new shstrtab: original + ".codesign\0"
    const char* codesignName = ".codesign";
    const size_t codesignNameLen = std::strlen(codesignName) + 1; // include null terminator
    size_t newShstrtabSize = shstrtabSize + codesignNameLen;
    size_t codesignNameOffset = shstrtabSize; // offset of ".codesign" in new shstrtab

    // 5. Compute the page-aligned offset for .codesign section
    // Place it right after the original file, aligned to PAGE_SIZE
    uint64_t codesignOffset = (origFileSize + PAGE_SIZE - 1) & ~static_cast<uint64_t>(PAGE_SIZE - 1);
    uint64_t paddingSize = codesignOffset - origFileSize;

    // 6. Build new Section Header Table
    // Original SHT size: e_shnum * 64
    // New SHT: original entries updated + 1 new entry for .codesign
    uint16_t newShnum = e_shnum + 1;
    size_t newShtSize = static_cast<size_t>(newShnum) * 64;

    // Update shstrtab section header to reflect new size and offset
    // (the current shstrtab entry in ehdr points to the old location;
    //  we'll create a new SHT with updated values)

    // SHT layout: [old entries (updated shstrtab)] + [new .codesign entry]
    // Old shstrtab section header index needs sh_size and sh_offset updated
    uint64_t newShstrtabOff = codesignOffset + PAGE_SIZE; // right after .codesign
    uint64_t newShtOff = newShstrtabOff + newShstrtabSize;

    // 7. Write output file
    std::ofstream out(outputFile, std::ios::binary | std::ios::trunc);
    if (!out) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Failed to create output file: %s", outputFile.c_str());
        return false;
    }

    // Write original ELF bytes unchanged
    out.write(origBytes.data(), origFileSize);

    // Write alignment padding (zeros)
    std::vector<char> padding(paddingSize, 0);
    out.write(padding.data(), paddingSize);

    // Write .codesign placeholder (PAGE_SIZE zeros, will be overwritten later)
    std::vector<char> codesignPlaceholder(PAGE_SIZE, 0);
    out.write(codesignPlaceholder.data(), PAGE_SIZE);

    // Build and write new shstrtab
    std::vector<char> newShstrtab(newShstrtabSize, 0);
    // Copy old shstrtab content
    std::memcpy(newShstrtab.data(), ehdr + shstrtabOff, shstrtabSize);
    // Append ".codesign\0"
    std::memcpy(newShstrtab.data() + shstrtabSize, codesignName, codesignNameLen);
    out.write(newShstrtab.data(), newShstrtabSize);

    // Build and write new Section Header Table
    std::vector<char> newSht(newShtSize, 0);

    // Copy old SHT entries, updating the shstrtab entry
    for (uint16_t i = 0; i < e_shnum; i++) {
        uint64_t oldEntryOff = e_shoff + static_cast<uint64_t>(i) * 64;
        const char* oldEntry = ehdr + oldEntryOff;
        char* newEntry = newSht.data() + static_cast<size_t>(i) * 64;

        if (i == e_shstrndx) {
            // Update shstrtab: new offset and size
            std::memcpy(newEntry, oldEntry, 64);
            writeU64(newEntry + 0x18, newShstrtabOff);  // sh_offset
            writeU64(newEntry + 0x20, newShstrtabSize); // sh_size
        } else {
            std::memcpy(newEntry, oldEntry, 64);
        }
    }

    // Add new .codesign section header (last entry)
    char* csEntry = newSht.data() + static_cast<size_t>(e_shnum) * 64;
    std::memset(csEntry, 0, 64);
    writeU32(csEntry + 0x00, static_cast<uint32_t>(codesignNameOffset)); // sh_name
    writeU32(csEntry + 0x04, 1);                // sh_type = SHT_PROGBITS
    writeU64(csEntry + 0x08, 0x2);              // sh_flags = SHF_ALLOC
    writeU64(csEntry + 0x10, 0);                // sh_addr = 0
    writeU64(csEntry + 0x18, codesignOffset);   // sh_offset
    writeU64(csEntry + 0x20, PAGE_SIZE);        // sh_size
    // sh_link = 0, sh_info = 0
    writeU64(csEntry + 0x30, PAGE_SIZE);        // sh_addralign = 4096
    // sh_entsize = 0

    out.write(newSht.data(), newShtSize);

    // 8. Patch ELF header: e_shoff, e_shnum, e_shstrndx
    writeU64(ehdr + 0x28, newShtOff);
    writeU16(ehdr + 0x3C, newShnum);
    writeU16(ehdr + 0x3E, e_shstrndx); // shstrtab index stays the same

    // Re-write the first 64 bytes (ELF header) with updated values
    out.seekp(0, std::ios::beg);
    out.write(origBytes.data(), 64);

    out.flush();
    out.close();

    csOffset = codesignOffset;

    // Preserve the input file's permissions on the output
    struct stat st;
    if (stat(inputFile.c_str(), &st) == 0) {
        chmod(outputFile.c_str(), st.st_mode);
    }

    PrintMsg("add codesign section success");
    SIGNATURE_TOOLS_LOGD("[SignElf] .codesign section offset: %lu, size: %lu", csOffset,
                         static_cast<uint64_t>(PAGE_SIZE));
    return true;
}

/*
 * ValidateProgramHeaders
 *
 * Checks that all PT_LOAD segments in the signed file have the same offset,
 * vaddr, filesz, memsz, flags, and align as in the original file.
 * Also checks that p_offset % p_align == p_vaddr % p_align.
 */
bool SignElf::ValidateProgramHeaders(const std::string& originalFile, const std::string& signedFile)
{
    ELFIO::elfio origReader;
    ELFIO::elfio signedReader;

    if (!origReader.load(originalFile)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Validate: Failed to load original ELF");
        return false;
    }
    if (!signedReader.load(signedFile)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Validate: Failed to load signed ELF");
        return false;
    }

    ELFIO::Elf_Half origSegNum = origReader.segments.size();
    ELFIO::Elf_Half signedSegNum = signedReader.segments.size();

    if (signedSegNum != origSegNum) {
        SIGNATURE_TOOLS_LOGE("[SignElf] Program Header count changed: %d -> %d",
                             origSegNum, signedSegNum);
        return false;
    }

    for (ELFIO::Elf_Half i = 0; i < origSegNum; i++) {
        const ELFIO::segment* origSeg = origReader.segments[i];
        const ELFIO::segment* signedSeg = signedReader.segments[i];

        if (origSeg->get_offset() != signedSeg->get_offset()) {
            SIGNATURE_TOOLS_LOGE("[SignElf] Segment %d p_offset changed: 0x%lx -> 0x%lx",
                                 i, origSeg->get_offset(), signedSeg->get_offset());
            return false;
        }
        if (origSeg->get_virtual_address() != signedSeg->get_virtual_address()) {
            SIGNATURE_TOOLS_LOGE("[SignElf] Segment %d p_vaddr changed: 0x%lx -> 0x%lx",
                                 i, origSeg->get_virtual_address(), signedSeg->get_virtual_address());
            return false;
        }
        if (origSeg->get_file_size() != signedSeg->get_file_size()) {
            SIGNATURE_TOOLS_LOGE("[SignElf] Segment %d p_filesz changed: 0x%lx -> 0x%lx",
                                 i, origSeg->get_file_size(), signedSeg->get_file_size());
            return false;
        }
        if (origSeg->get_memory_size() != signedSeg->get_memory_size()) {
            SIGNATURE_TOOLS_LOGE("[SignElf] Segment %d p_memsz changed: 0x%lx -> 0x%lx",
                                 i, origSeg->get_memory_size(), signedSeg->get_memory_size());
            return false;
        }
        if (origSeg->get_flags() != signedSeg->get_flags()) {
            SIGNATURE_TOOLS_LOGE("[SignElf] Segment %d p_flags changed: 0x%x -> 0x%x",
                                 i, origSeg->get_flags(), signedSeg->get_flags());
            return false;
        }
        if (origSeg->get_align() != signedSeg->get_align()) {
            SIGNATURE_TOOLS_LOGE("[SignElf] Segment %d p_align changed: 0x%lx -> 0x%lx",
                                 i, origSeg->get_align(), signedSeg->get_align());
            return false;
        }

        // Check p_offset % p_align == p_vaddr % p_align for PT_LOAD segments
        if (origSeg->get_type() == ELFIO::PT_LOAD && origSeg->get_align() > 1) {
            uint64_t align = origSeg->get_align();
            if ((signedSeg->get_offset() % align) != (signedSeg->get_virtual_address() % align)) {
                SIGNATURE_TOOLS_LOGE(
                    "[SignElf] Segment %d p_offset%%p_align != p_vaddr%%p_align: "
                    "offset=0x%lx vaddr=0x%lx align=0x%lx",
                    i, signedSeg->get_offset(), signedSeg->get_virtual_address(), align);
                return false;
            }
        }
    }
    return true;
}
} // namespace SignatureTools
} // namespace OHOS