#include <relinker/parsing/SelfUnwrapper.hpp>
#include <domain/Types.hpp>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint32_t SelfMagic = 0x1d3d154f;
constexpr std::uint32_t SelfMagicKernel = 0xeef51454;
constexpr std::uint64_t ElfHeaderOffset = 0x1a0;
constexpr std::uint64_t ProgramTableOffset = 0x40;
constexpr std::uint32_t PtLoad = 1;
constexpr std::uint32_t PtDynamic = 2;
constexpr std::uint32_t PtNote = 4;
constexpr std::uint32_t PtTls = 7;
constexpr std::uint32_t SceComment = 0x6fffff00;
constexpr std::uint32_t SceVersion = 0x6fffff01;
constexpr std::uint64_t FirstRegion = 0x400;
constexpr std::uint64_t Page = 0x1000;

struct Seg {
    std::uint32_t Type;
    std::uint32_t Flags;
    std::uint64_t Offset;
    std::uint64_t Vaddr;
    std::uint64_t Size;
    std::uint64_t Align;
};

struct Rec {
    std::uint64_t Flags;
    std::uint64_t Offset;
    std::uint64_t Size;
};

struct Header {
    std::uint32_t Type;
    std::uint32_t Flags;
    std::uint64_t Offset;
    std::uint64_t Vaddr;
    std::uint64_t Paddr;
    std::uint64_t Size;
    std::uint64_t Memory;
    std::uint64_t Align;
};

using Payloads = std::vector<std::pair<std::uint64_t, Bytes>>;

void Require(const bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

template<typename TValue>
void Write(Bytes& bytes, const std::uint64_t offset, const TValue value) {
    if (offset + sizeof(value) > bytes.size()) bytes.resize(offset + sizeof(value));
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

template<typename TValue>
TValue Read(const Bytes& bytes, const std::uint64_t offset) {
    Require(offset + sizeof(TValue) <= bytes.size(), "read past the output");
    TValue value;
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}

void Put(Bytes& bytes, const std::uint64_t offset, const Bytes& block) {
    if (offset + block.size() > bytes.size()) bytes.resize(offset + block.size());
    std::copy(block.begin(), block.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
}

Bytes Pattern(const unsigned seed, const std::size_t size) {
    Bytes bytes(size);
    for (std::size_t index = 0; index < size; ++index) bytes[index] = static_cast<std::uint8_t>((seed + index * 7) % 251);
    return bytes;
}

Bytes Repeat(const std::string& text, const std::size_t times) {
    Bytes bytes;
    for (std::size_t index = 0; index < times; ++index) bytes.insert(bytes.end(), text.begin(), text.end());
    return bytes;
}

Bytes Slice(const Bytes& bytes, const std::size_t begin, const std::size_t size) {
    return Bytes(bytes.begin() + static_cast<std::ptrdiff_t>(begin), bytes.begin() + static_cast<std::ptrdiff_t>(begin + size));
}

Bytes BuildElf(const std::vector<Seg>& segments, const std::uint64_t programOffset) {
    Bytes elf(0x40);
    const std::uint8_t identification[] = {0x7f, 'E', 'L', 'F', 2, 1, 1, 9};
    std::memcpy(elf.data(), identification, sizeof identification);
    Write<std::uint16_t>(elf, 0x10, 0xfe10);
    Write<std::uint16_t>(elf, 0x12, 0x3e);
    Write<std::uint32_t>(elf, 0x14, 1);
    Write<std::uint64_t>(elf, 0x18, 0x70);
    Write<std::uint64_t>(elf, 0x20, programOffset);
    Write<std::uint16_t>(elf, 0x34, 0x40);
    Write<std::uint16_t>(elf, 0x36, 56);
    Write<std::uint16_t>(elf, 0x38, static_cast<std::uint16_t>(segments.size()));
    Write<std::uint16_t>(elf, 0x3a, 0x40);
    elf.resize(programOffset);
    for (const auto& segment : segments) {
        const auto offset = elf.size();
        Write<std::uint32_t>(elf, offset, segment.Type);
        Write<std::uint32_t>(elf, offset + 4, segment.Flags);
        Write<std::uint64_t>(elf, offset + 8, segment.Offset);
        Write<std::uint64_t>(elf, offset + 16, segment.Vaddr);
        Write<std::uint64_t>(elf, offset + 24, segment.Vaddr);
        Write<std::uint64_t>(elf, offset + 32, segment.Size);
        Write<std::uint64_t>(elf, offset + 40, segment.Size);
        Write<std::uint64_t>(elf, offset + 48, segment.Align);
    }
    return elf;
}

Bytes Container(const std::vector<Seg>& segments, const std::vector<Rec>& records, const Payloads& payloads, const std::uint32_t magic = SelfMagic,
                const bool innerElf = true, const std::uint64_t programOffset = ProgramTableOffset) {
    std::uint64_t size = FirstRegion;
    for (const auto& [offset, block] : payloads) size = std::max<std::uint64_t>(size, offset + block.size());
    Bytes data(size);
    Write<std::uint32_t>(data, 0, magic);
    for (std::size_t index = 0; index < records.size(); ++index) {
        const auto offset = 0x40 + index * 0x20;
        Write<std::uint64_t>(data, offset, records[index].Flags);
        Write<std::uint64_t>(data, offset + 8, records[index].Offset);
        Write<std::uint64_t>(data, offset + 16, records[index].Size);
        Write<std::uint64_t>(data, offset + 24, records[index].Size);
    }
    if (innerElf) Put(data, ElfHeaderOffset, BuildElf(segments, programOffset));
    for (const auto& [offset, block] : payloads) Put(data, offset, block);
    return data;
}

std::vector<Seg> DefaultSegments() { return {{PtLoad, 1, 0x1234, 0x0, 0x100, Page}, {PtLoad, 4, 0x1500, 0x1000, 0x80, Page}, {PtDynamic, 6, 0x1580, 0x1040, 0x10, 8}}; }
std::vector<Rec> DefaultRecords() { return {{0x2804, 0x800, 0x100}, {0x310004, 0x910, 0x20}, {0x102804, 0xa00, 0x80}}; }
Payloads DefaultPayloads() { return {{0x800, Pattern(1, 0x100)}, {0xa00, Pattern(9, 0x80)}}; }
Bytes DefaultContainer() { return Container(DefaultSegments(), DefaultRecords(), DefaultPayloads()); }

std::vector<Header> Headers(const Bytes& data) {
    const auto programOffset = Read<std::uint64_t>(data, 0x20);
    const auto count = Read<std::uint16_t>(data, 0x38);
    std::vector<Header> headers;
    for (std::size_t index = 0; index < count; ++index) {
        const auto offset = programOffset + index * 56;
        headers.push_back({Read<std::uint32_t>(data, offset), Read<std::uint32_t>(data, offset + 4), Read<std::uint64_t>(data, offset + 8),
                           Read<std::uint64_t>(data, offset + 16), Read<std::uint64_t>(data, offset + 24), Read<std::uint64_t>(data, offset + 32),
                           Read<std::uint64_t>(data, offset + 40), Read<std::uint64_t>(data, offset + 48)});
    }
    return headers;
}

Bytes Content(const Bytes& data, const Header& header) {
    Require(header.Offset + header.Size <= data.size(), "segment past the output");
    return Slice(data, header.Offset, header.Size);
}

const Header& OfType(const std::vector<Header>& headers, const std::uint32_t type, const std::size_t nth = 0) {
    std::size_t seen = 0;
    for (const auto& header : headers)
        if (header.Type == type && seen++ == nth) return header;
    throw std::runtime_error("no program header of type " + std::to_string(type));
}

void RequireAligned(const Header& header) {
    if (header.Align > 1) Require(header.Offset % header.Align == header.Vaddr % header.Align, "offset not congruent to vaddr");
}

void Refused(const Bytes& container, const std::string& message, const std::uint64_t limit = Relinker::SelfMaxAlignmentPadding) {
    try {
        Relinker::UnwrapSelf(container, limit);
    } catch (const Domain::RelinkerException& error) {
        Require(std::string(error.what()).find(message) != std::string::npos, std::string("refused with '") + error.what() + "', expected '" + message + "'");
        return;
    }
    throw std::runtime_error("accepted, expected refusal: " + message);
}

void SetField(Bytes& container, const std::size_t header, const std::size_t field, const std::uint64_t value) {
    Write<std::uint64_t>(container, ElfHeaderOffset + ProgramTableOffset + header * 56 + field, value);
}

}

int main() {
    const std::vector<std::pair<std::string, std::function<void()>>> cases{
        {"record table places the segments and keeps the alignment", [] {
            const auto data = Relinker::UnwrapSelf(DefaultContainer());
            const auto headers = Headers(data);
            const auto& text = OfType(headers, PtLoad, 0);
            const auto& readOnly = OfType(headers, PtLoad, 1);
            RequireAligned(text);
            RequireAligned(readOnly);
            Require(text.Offset % Page == 0 && text.Offset != 0x1234, "text offset");
            Require(Content(data, text) == Pattern(1, 0x100), "text bytes");
            Require(readOnly.Offset != 0x1500 && Content(data, readOnly) == Pattern(9, 0x80), "read-only bytes");
            const auto& dynamic = OfType(headers, PtDynamic);
            Require(dynamic.Offset == readOnly.Offset + 0x40 && dynamic.Offset % 8 == 0x1040 % 8, "dynamic offset");
            Require(Read<std::uint64_t>(data, 0x28) == 0 && Read<std::uint16_t>(data, 0x3c) == 0 && Read<std::uint16_t>(data, 0x3e) == 0, "section table cleared");
        }},
        {"self detection and the kernel magic", [] {
            Require(Relinker::IsSelfContainer(DefaultContainer()), "SELF magic");
            Require(!Relinker::IsSelfContainer(Bytes{0x7f, 'E', 'L', 'F'}) && !Relinker::IsSelfContainer(Bytes{0x4f, 0x15}), "not SELF");
            const auto data = Relinker::UnwrapSelf(Container(DefaultSegments(), DefaultRecords(), DefaultPayloads(), SelfMagicKernel));
            Require(Headers(data).size() == 3, "kernel magic converts");
        }},
        {"inputs that are not a container are refused", [] {
            Refused(Bytes(0x10), "file is smaller than the SELF header area");
            Bytes package(FirstRegion + 4);
            const std::uint8_t magic[] = {0x7f, 'C', 'N', 'T'};
            std::memcpy(package.data(), magic, sizeof magic);
            Refused(package, "not a SELF container (magic 0x544e437f)");
            Refused(Bytes(FirstRegion), "not a SELF container (magic 0x0)");
            Refused(Container(DefaultSegments(), DefaultRecords(), DefaultPayloads(), SelfMagic, false), "no inner ELF header");
            Bytes truncated(FirstRegion);
            Write<std::uint32_t>(truncated, 0, SelfMagic);
            const std::uint8_t elf[] = {0x7f, 'E', 'L', 'F'};
            std::memcpy(truncated.data() + FirstRegion - 4, elf, sizeof elf);
            Refused(truncated, "inner ELF header is truncated");
        }},
        {"unsupported inner ELF headers are refused", [] {
            for (const std::uint16_t machine : {0, 3, 40, 183, 0x3e00, 0xffff}) {
                auto container = DefaultContainer();
                Write<std::uint16_t>(container, ElfHeaderOffset + 0x12, machine);
                Refused(container, "unsupported inner ELF machine " + std::to_string(machine) + " (expected 62)");
            }
            for (const std::uint16_t size : {0, 52, 63, 65, 0x4000, 0xffff}) {
                auto container = DefaultContainer();
                Write<std::uint16_t>(container, ElfHeaderOffset + 0x34, size);
                Refused(container, "invalid inner ELF header size " + std::to_string(size) + " (expected 64)");
            }
            for (const auto& [offset, value] : std::vector<std::pair<std::size_t, std::uint8_t>>{{4, 1}, {5, 2}}) {
                auto container = DefaultContainer();
                container[ElfHeaderOffset + offset] = value;
                Refused(container, "inner ELF is not 64-bit little-endian");
            }
            for (const unsigned identification : {0u, 1u, 2u, 255u}) {
                for (const std::uint32_t version : {0u, 1u, 2u, 0x1000001u, 0xffffffffu}) {
                    if (identification == 1 && version == 1) continue;
                    auto container = DefaultContainer();
                    container[ElfHeaderOffset + 6] = static_cast<std::uint8_t>(identification);
                    Write<std::uint32_t>(container, ElfHeaderOffset + 0x14, version);
                    Refused(container, "unsupported inner ELF version (identification " + std::to_string(identification) + ", object " + std::to_string(version) + ")");
                }
            }
        }},
        {"program header tables that overlap or overrun are refused", [] {
            for (const std::uint64_t offset : {0, 8, 32, 63}) {
                auto container = DefaultContainer();
                Write<std::uint64_t>(container, ElfHeaderOffset + 0x20, offset);
                Refused(container, "ELF program header table overlaps the ELF header");
            }
            for (const auto& [offset, count] : std::vector<std::pair<std::uint64_t, std::uint16_t>>{{~0ull, 3}, {ProgramTableOffset, 0xffff}}) {
                auto container = DefaultContainer();
                Write<std::uint64_t>(container, ElfHeaderOffset + 0x20, offset);
                Write<std::uint16_t>(container, ElfHeaderOffset + 0x38, count);
                Refused(container, "ELF program header table does not fit the file");
            }
        }},
        {"invalid load metadata is refused", [] {
            for (const auto& [field, value, message] : std::vector<std::tuple<std::size_t, std::uint64_t, std::string>>{
                     {40, 0xff, "file size exceeds memory size"}, {48, 3, "alignment is not a power of two"},
                     {48, 24, "alignment is not a power of two"}, {16, ~0ull, "memory range exceeds ELF64"}}) {
                auto container = DefaultContainer();
                SetField(container, 0, field, value);
                Refused(container, message);
            }
            for (const std::uint64_t alignment : {0, 1}) {
                auto container = DefaultContainer();
                SetField(container, 0, 48, alignment);
                const auto data = Relinker::UnwrapSelf(container);
                const auto headers = Headers(data);
                Require(headers[0].Align == alignment && Content(data, headers[0]) == Pattern(1, 0x100), "alignment 0 and 1 kept");
            }
        }},
        {"a container whose load segments look encrypted is refused", [] {
            Bytes randomLike;
            for (int repeat = 0; repeat < 4; ++repeat)
                for (int value = 0; value < 256; ++value) randomLike.push_back(static_cast<std::uint8_t>(value));
            Refused(Container({{PtLoad, 1, 0x1234, 0x0, 0x400, Page}, {PtLoad, 4, 0x1500, 0x1000, 0x400, Page}}, {{0x2804, 0x800, 0x400}, {0x102804, 0x1000, 0x400}},
                              {{0x800, randomLike}, {0x1000, randomLike}}),
                    "every load segment looks encrypted: segment 0 at 0x800 (8.00 bits per byte), segment 1 at 0x1000 (8.00 bits per byte)");
            const auto data = Relinker::UnwrapSelf(Container({{PtLoad, 1, 0x1234, 0x0, 0x400, Page}, {PtLoad, 4, 0x1500, 0x1000, 0x100, Page}},
                                                             {{0x2804, 0x800, 0x400}, {0x102804, 0x1000, 0x100}}, {{0x800, randomLike}, {0x1000, Bytes(0x100, 7)}}));
            Require(Headers(data).size() == 2, "one plain load segment is enough");
        }},
        {"an empty segment at the end of a load segment is placed after it", [] {
            auto segments = DefaultSegments();
            segments.push_back({PtTls, 4, 0x1580, 0x1080, 0x0, 8});
            const auto headers = Headers(Relinker::UnwrapSelf(Container(segments, DefaultRecords(), DefaultPayloads())));
            const auto& tls = OfType(headers, PtTls);
            Require(tls.Offset == OfType(headers, PtLoad, 1).Offset + 0x80 && tls.Size == 0, "TLS after the load");
        }},
        {"contained segments keep stronger alignment than their load", [] {
            const auto payload = Repeat("TLS template data", 16);
            for (const auto kind : {PtDynamic, PtTls}) {
                for (const std::uint64_t size : {0, 0x20}) {
                    for (const bool recorded : {false, true}) {
                        std::vector<Rec> records;
                        if (recorded) records.push_back({0x800, 0x800, payload.size()});
                        if (recorded && size) records.push_back({0x100800, 0x840, size});
                        const auto data = Relinker::UnwrapSelf(Container({{PtLoad, 6, 0x2000, 0x4000, payload.size(), 0x100}, {kind, 4, 0x2040, 0x4040, size, Page}},
                                                                         records, {{recorded ? 0x800u : 0x2000u, payload}}));
                        const auto headers = Headers(data);
                        for (const auto& header : headers) RequireAligned(header);
                        Require(headers[1].Offset - headers[0].Offset == 0x40, "embedded delta");
                        Require(Content(data, headers[0]) == payload && Slice(data, headers[1].Offset, size) == Slice(payload, 0x40, size), "embedded bytes");
                    }
                }
            }
        }},
        {"incompatible contained alignment is refused", [] {
            Refused(Container({{PtLoad, 6, 0x2000, 0x4000, 0x100, 0x100}, {PtTls, 4, 0x2040, 0x40c0, 0x20, Page}}, {{0x800, 0x800, 0x100}, {0x100800, 0x840, 0x20}},
                              {{0x800, Repeat("TLS data", 32)}}),
                    "segment 1 has incompatible alignment within its output region");
        }},
        {"the alignment padding limit holds and is cumulative", [] {
            Refused(Container({{PtLoad, 6, 0x2000, 0x4000, 0x100, 0x100}, {PtTls, 4, 0x2040, 0x4040, 0x20, Page}}, {}, {{0x2000, Repeat("TLS data", 32)}}),
                    "alignment requires more than", 0x800);
            for (const bool empty : {false, true}) {
                std::vector<Rec> records{{0x800, 0x800, 0x20}};
                Payloads payloads{{0x800, Pattern(1, 0x20)}};
                if (!empty) {
                    records.push_back({0x100800, 0xa00, 0x10});
                    payloads.push_back({0xa00, Pattern(9, 0x10)});
                }
                const auto container = Container({{PtLoad, 5, 0x1234, 0x80, 0x20, 0x100}, {PtLoad, 6, 0x5678, 0x580, empty ? 0u : 0x10u, 0x1000}}, records, payloads);
                Refused(container, "alignment requires more than", 0x15f);
                const auto data = Relinker::UnwrapSelf(container, 0x160);
                const auto headers = Headers(data);
                for (const auto& header : headers) RequireAligned(header);
                Require(Slice(data, headers[0].Offset, 0x20) == Pattern(1, 0x20), "first payload");
                if (!empty) Require(Slice(data, headers[1].Offset, 0x10) == Pattern(9, 0x10), "second payload");
            }
            Refused(Container({{PtLoad, 6, 0, (1ull << 40) - 1, 0, 1ull << 40}}, {}, {}), "segment alignment requires more than");
            Refused(Container({{PtLoad, 5, 0x1234, (1ull << 40) - 1, 0x100, 1ull << 40}}, {{0x2804, 0x800, 0x100}}, {{0x800, Bytes(0x100, 'x')}}),
                    "alignment requires more than");
            const auto data = Relinker::UnwrapSelf(Container({{PtLoad, 5, 0x1234, FirstRegion + 0x10, 0x100, 1ull << 40}}, {{0x2804, 0x800, 0x100}}, {{0x800, Bytes(0x100, 'x')}}), 0x10);
            Require(Headers(data)[0].Offset == FirstRegion + 0x10, "large alignment with small padding");
        }},
        {"segments after the recorded comment are read from the container", [] {
            auto segments = DefaultSegments();
            segments.insert(segments.end(), {{SceComment, 4, 0x15a0, 0x0, 0x20, 0x10}, {PtNote, 4, 0x15c0, 0x0, 0x18, 4}, {SceVersion, 4, 0x15d8, 0x0, 0x10, 1}});
            auto records = DefaultRecords();
            records.insert(records.end(), {{0x410004, 0xa80, 0x20}, {0x302804, 0xaa0, 0x20}});
            auto payloads = DefaultPayloads();
            payloads.insert(payloads.end(), {{0xaa0, Pattern(11, 0x20)}, {0xac0, Pattern(13, 0x10)}});
            const auto data = Relinker::UnwrapSelf(Container(segments, records, payloads));
            const auto headers = Headers(data);
            Require(Content(data, OfType(headers, SceComment)) == Pattern(11, 0x20), "comment bytes");
            Require(Content(data, OfType(headers, SceVersion)) == Pattern(13, 0x10), "version bytes");
            Require(OfType(headers, PtNote).Size == 0, "note without file bytes");
            for (const std::size_t stored : {0, 8}) {
                auto shortSegments = segments;
                shortSegments.back().Align = 0x10;
                auto shortPayloads = DefaultPayloads();
                shortPayloads.push_back({0xaa0, Pattern(11, 0x20)});
                if (stored) shortPayloads.push_back({0xac0, Pattern(13, stored)});
                const auto container = Container(shortSegments, records, shortPayloads);
                Require(container.size() == 0xac0 + stored, "container ends early");
                const auto shortData = Relinker::UnwrapSelf(container);
                const auto shortHeaders = Headers(shortData);
                const auto& version = OfType(shortHeaders, SceVersion);
                Require(version.Offset == 0 && version.Size == 0, "unstored version without file bytes");
                Require(Content(shortData, OfType(shortHeaders, SceComment)) == Pattern(11, 0x20), "comment kept");
            }
        }},
        {"stale offsets that do not fit are refused", [] {
            auto segments = DefaultSegments();
            segments.push_back({SceComment, 4, 0x100, 0, 0x20, 1});
            Refused(Container(segments, DefaultRecords(), DefaultPayloads()), "does not fit the file");
            segments = DefaultSegments();
            segments[2] = {PtDynamic, 6, 0x49000000001580, 0x1040, 0x10, 8};
            segments.push_back({SceComment, 4, 0x1600, 0, 0x4000000000000000, 1});
            Refused(Container(segments, DefaultRecords(), DefaultPayloads()), "does not fit the file");
            segments = DefaultSegments();
            segments.push_back({PtLoad, 6, 0x1900, 0x4000, 1, Page});
            Refused(Container(segments, DefaultRecords(), DefaultPayloads()), "segment 3 does not fit the file");
        }},
        {"segments outside the file-backed load range are refused", [] {
            for (const auto& [address, size, memory] : std::vector<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>>{{0x1078, 0x10, 0x80}, {0x1078, 0x10, 0x100}, {0x1080, 0x10, 0x100}}) {
                for (const auto kind : {PtDynamic, PtTls}) {
                    auto segments = DefaultSegments();
                    segments[2] = {kind, 4, 0x1580, address, size, 8};
                    auto payloads = DefaultPayloads();
                    payloads.push_back({0xa80, Pattern(23, 0x100)});
                    auto container = Container(segments, DefaultRecords(), payloads);
                    SetField(container, 1, 40, memory);
                    Refused(container, "file-backed range of PT_LOAD 1");
                }
            }
            auto segments = DefaultSegments();
            segments.insert(segments.end(), {{PtLoad, 6, 0x1900, 0x4000, 0, Page}, {PtTls, 4, 0x1900, 0x4000, 0x10, 8}});
            auto container = Container(segments, DefaultRecords(), DefaultPayloads());
            SetField(container, 3, 40, 0x2000);
            Refused(container, "file-backed range of PT_LOAD 3");
        }},
        {"file-empty loads keep their alignment and memory", [] {
            for (const auto& [alignment, address] : std::vector<std::pair<std::uint64_t, std::uint64_t>>{
                     {0, 0x4010}, {1, 0x4010}, {Page, 0x4010}, {Page, 0x4fff}, {0x10000, 0x1ffff}, {1ull << 40, (1ull << 40) + 16}}) {
                for (const std::uint64_t memory : {0, 0x2000}) {
                    auto segments = DefaultSegments();
                    segments.push_back({PtLoad, 6, ~0ull, address, 0, alignment});
                    auto container = Container(segments, DefaultRecords(), DefaultPayloads());
                    SetField(container, 3, 40, memory);
                    const auto data = Relinker::UnwrapSelf(container);
                    const auto headers = Headers(data);
                    const auto& load = headers[3];
                    Require(load.Vaddr == address && load.Size == 0 && load.Memory == memory && load.Align == alignment, "empty load metadata");
                    Require(load.Offset % std::max<std::uint64_t>(alignment, 1) == address % std::max<std::uint64_t>(alignment, 1) && load.Offset <= data.size(), "empty load offset");
                    Require(Content(data, headers[0]) == Pattern(1, 0x100) && Content(data, headers[1]) == Pattern(9, 0x80), "loads intact");
                }
            }
        }},
        {"zero-size segments outside a file-backed range are accepted", [] {
            auto segments = DefaultSegments();
            segments.push_back({PtTls, 4, 0x1900, 0x2000, 0, 8});
            const auto& tls = OfType(Headers(Relinker::UnwrapSelf(Container(segments, DefaultRecords(), DefaultPayloads()))), PtTls);
            Require(tls.Size == 0 && tls.Offset == 0, "zero-size TLS");
        }},
        {"declared offsets are used when the container has no records", [] {
            const auto data = Relinker::UnwrapSelf(Container({{PtLoad, 1, 0x800, 0x0, 0x40, 0x1000}, {PtLoad, 4, 0x900, 0x1000, 0x40, 0x1000}}, {},
                                                             {{0x800, Pattern(3, 0x40)}, {0x900, Pattern(5, 0x40)}}));
            const auto headers = Headers(data);
            Require(Content(data, headers[0]) == Pattern(3, 0x40) && Content(data, headers[1]) == Pattern(5, 0x40), "declared bytes");
            for (const auto& header : headers) RequireAligned(header);
        }},
        {"a file-backed load uses the first congruent offset after the headers", [] {
            Bytes payload;
            for (int repeat = 0; repeat < 8; ++repeat) {
                const auto part = Pattern(3, 0x20);
                payload.insert(payload.end(), part.begin(), part.end());
            }
            for (const auto& [programOffset, alignment, address, expected] : std::vector<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t>>{
                     {ProgramTableOffset, 0, 0x1400, 0x400}, {ProgramTableOffset, 1, 0x1400, 0x400}, {ProgramTableOffset, 8, 0x1003, 0x403},
                     {ProgramTableOffset, Page, 0x1400, 0x400}, {ProgramTableOffset, Page, 0x1480, 0x480}, {ProgramTableOffset, Page, 0x1200, 0x1200},
                     {ProgramTableOffset, Page, 0x1000, 0x1000}, {ProgramTableOffset, Page, 0x1fff, 0xfff}, {0xff0, Page, 0x2100, 0x1100},
                     {ProgramTableOffset, 1ull << 63, 0x480, 0x480}}) {
                const auto data = Relinker::UnwrapSelf(Container({{PtLoad, 5, 0x1234, address, payload.size(), alignment}}, {{0x2804, 0x2000, payload.size()}},
                                                                 {{0x2000, payload}}, SelfMagic, true, programOffset));
                const auto& load = Headers(data)[0];
                Require(load.Offset == expected, "first congruent offset " + std::to_string(expected));
                Require(Content(data, load) == payload && data.size() == expected + payload.size(), "load bytes and size");
            }
        }},
        {"program headers do not overwrite the first load payload", [] {
            Bytes payload;
            for (int repeat = 0; repeat < 8; ++repeat) {
                const auto part = Pattern(3, 0x20);
                payload.insert(payload.end(), part.begin(), part.end());
            }
            for (const auto& [count, programOffset] : std::vector<std::pair<std::size_t, std::uint64_t>>{{74, ProgramTableOffset}, {3, 0xff0}}) {
                std::vector<Seg> segments{{PtLoad, 5, 0x1234, 0, payload.size(), Page}};
                segments.resize(count, Seg{0, 0, 0, 0, 0, 0});
                const auto data = Relinker::UnwrapSelf(Container(segments, {{0x2804, 0x2000, payload.size()}}, {{0x2000, payload}}, SelfMagic, true, programOffset));
                const auto headers = Headers(data);
                Require(headers.size() == count && Content(data, headers[0]) == payload && headers[0].Offset >= programOffset + count * 56, "payload after the table");
            }
        }},
        {"overlapping and recorded load sources keep their bytes and alignment", [] {
            const auto payload = Repeat("overlapping load payload", 16);
            const auto data = Relinker::UnwrapSelf(Container({{PtLoad, 5, 0x1000, 0x1000, 0x100, 0x100}, {PtLoad, 6, 0x1080, 0x3080, 0x100, 0x100}, {PtTls, 4, 0x1090, 0x3090, 0x10, Page}},
                                                             {}, {{0x1000, payload}}));
            const auto headers = Headers(data);
            const std::uint64_t deltas[] = {0, 0x80, 0x90};
            for (std::size_t index = 0; index < 3; ++index) {
                RequireAligned(headers[index]);
                Require(Content(data, headers[index]) == Slice(payload, deltas[index], headers[index].Size), "inferred overlap bytes");
            }
            Require(headers[2].Offset - headers[1].Offset == headers[2].Vaddr - headers[1].Vaddr, "TLS stays in its host");
            const auto shared = Repeat("shared load payload", 16);
            for (const auto& [delta, size] : std::vector<std::pair<std::uint64_t, std::uint64_t>>{{0, shared.size()}, {0, 0x80}, {0x40, 0x80}}) {
                for (const bool recorded : {false, true}) {
                    const std::uint64_t source = recorded ? 0x800 : 0x2000;
                    std::vector<Rec> records;
                    if (recorded) records = {{0x800, source, shared.size()}, {0x100800, source + delta, size}};
                    const auto sharedData = Relinker::UnwrapSelf(Container({{PtLoad, 5, 0x2000, 0x1000, shared.size(), Page}, {PtLoad, 6, 0x2000 + delta, 0x4000 + delta, size, 2 * Page}},
                                                                           records, {{source, shared}}));
                    const auto sharedHeaders = Headers(sharedData);
                    RequireAligned(sharedHeaders[0]);
                    RequireAligned(sharedHeaders[1]);
                    Require(Content(sharedData, sharedHeaders[0]) == shared && Content(sharedData, sharedHeaders[1]) == Slice(shared, delta, size), "shared load bytes");
                }
            }
        }},
        {"the abi version byte is preserved", [] {
            for (const auto magic : {SelfMagic, SelfMagicKernel}) {
                for (const unsigned abi : {0u, 1u, 255u}) {
                    auto container = Container(DefaultSegments(), DefaultRecords(), DefaultPayloads(), magic);
                    container[ElfHeaderOffset + 8] = static_cast<std::uint8_t>(abi);
                    const auto data = Relinker::UnwrapSelf(container);
                    Require(data[6] == 1 && Read<std::uint32_t>(data, 0x14) == 1 && data[8] == abi, "identification kept");
                }
            }
        }},
    };
    std::size_t failures = 0;
    for (const auto& [name, test] : cases) {
        try {
            test();
            std::cout << "PASS: " << name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "FAIL: " << name << ": " << error.what() << '\n';
        }
    }
    return failures == 0 ? 0 : 1;
}
