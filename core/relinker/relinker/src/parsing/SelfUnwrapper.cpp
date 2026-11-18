#include <relinker/parsing/SelfUnwrapper.hpp>
#include <domain/Types.hpp>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <deque>
#include <optional>
#include <set>
#include <sstream>
#include <string>

namespace Relinker {

namespace {

using Wide = __int128;

constexpr std::uint32_t SelfMagic = 0x1d3d154f;
constexpr std::uint32_t SelfMagicKernel = 0xeef51454;
constexpr std::uint64_t RecordOffset = 0x40;
constexpr std::uint64_t RecordSize = 0x20;
constexpr std::uint64_t RecordHasSegment = 0x800;
constexpr int RecordSegmentShift = 20;
constexpr std::uint64_t FirstRegion = 0x400;
constexpr std::uint32_t PtLoad = 1;
constexpr std::uint32_t PtNote = 4;
constexpr double EntropyLimit = 7.5;
constexpr std::uint64_t EntropySample = 0x10000;
constexpr std::uint64_t ProgramHeaderSize = 56;

struct Record {
    std::uint64_t Flags;
    std::uint64_t Segment;
    std::uint64_t Size;
};

struct Segment {
    std::size_t Index;
    std::uint32_t Type;
    std::uint32_t Flags;
    std::uint64_t Offset;
    std::uint64_t Vaddr;
    Wide Size;
    Wide Memory;
    std::uint64_t Align;
    Wide Source;
    std::optional<std::size_t> Host;
    std::uint64_t New = 0;
};

struct Region {
    std::uint64_t Old;
    std::uint64_t Size;
    std::uint64_t Vaddr;
    std::uint64_t Align;
    std::uint64_t New = 0;
};

[[noreturn]] void Refuse(const std::string& message) { throw Domain::RelinkerException(message); }

std::string Hex(const std::uint64_t value) {
    std::ostringstream text;
    text << "0x" << std::hex << value;
    return text.str();
}

template<typename TValue>
TValue Read(const std::vector<std::uint8_t>& bytes, const std::uint64_t offset) {
    TValue value;
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}

template<typename TValue>
void Write(std::vector<std::uint8_t>& bytes, const std::uint64_t offset, const TValue value) { std::memcpy(bytes.data() + offset, &value, sizeof(value)); }

bool PowerOfTwo(const std::uint64_t value) { return value != 0 && (value & (value - 1)) == 0; }

double Entropy(const std::uint8_t* data, const std::size_t size) {
    if (size == 0) return 0.0;
    std::array<std::size_t, 256> counts{};
    for (std::size_t index = 0; index < size; ++index) ++counts[data[index]];
    double result = 0.0;
    for (const auto count : counts) {
        if (count == 0) continue;
        const double share = static_cast<double>(count) / static_cast<double>(size);
        result -= share * std::log2(share);
    }
    return result;
}

std::vector<Record> ReadRecords(const std::vector<std::uint8_t>& data) {
    std::vector<Record> records;
    for (std::uint64_t offset = RecordOffset; offset + RecordSize <= FirstRegion; offset += RecordSize) {
        const auto flags = Read<std::uint64_t>(data, offset);
        const auto segment = Read<std::uint64_t>(data, offset + 8);
        const auto size = Read<std::uint64_t>(data, offset + 16);
        const auto again = Read<std::uint64_t>(data, offset + 24);
        if (size == 0 || size != again) break;
        if (segment >= data.size() || segment < 0x350 || segment % 0x10 != 0) break;
        if (size > data.size()) break;
        records.push_back({flags, segment, size});
    }
    return records;
}

struct InnerElf {
    std::uint64_t Offset;
    std::vector<std::uint8_t> Header;
    std::uint64_t ProgramOffset;
    std::vector<Segment> Segments;
};

InnerElf ParseElf(const std::vector<std::uint8_t>& data) {
    static constexpr std::uint8_t Magic[] = {0x7f, 'E', 'L', 'F'};
    const auto found = std::search(data.begin(), data.end(), std::begin(Magic), std::end(Magic));
    if (found == data.end()) Refuse("no inner ELF header");
    const auto inner = static_cast<std::uint64_t>(found - data.begin());
    if (inner + 0x40 > data.size()) Refuse("inner ELF header is truncated");
    InnerElf elf{inner, std::vector<std::uint8_t>(found, found + 0x40), 0, {}};
    const auto& header = elf.Header;
    if (header[4] != 2 || header[5] != 1) Refuse("inner ELF is not 64-bit little-endian");
    const auto version = Read<std::uint32_t>(header, 0x14);
    if (header[6] != 1 || version != 1)
        Refuse("unsupported inner ELF version (identification " + std::to_string(header[6]) + ", object " + std::to_string(version) + ")");
    elf.ProgramOffset = Read<std::uint64_t>(header, 0x20);
    const auto machine = Read<std::uint16_t>(header, 0x12);
    if (machine != 62) Refuse("unsupported inner ELF machine " + std::to_string(machine) + " (expected 62)");
    const auto headerSize = Read<std::uint16_t>(header, 0x34);
    if (headerSize != 64) Refuse("invalid inner ELF header size " + std::to_string(headerSize) + " (expected 64)");
    const auto entrySize = Read<std::uint16_t>(header, 0x36);
    const auto count = Read<std::uint16_t>(header, 0x38);
    if (entrySize != ProgramHeaderSize || count == 0)
        Refuse("program header table is " + std::to_string(count) + " entries of " + std::to_string(entrySize) + " bytes");
    if (elf.ProgramOffset < header.size()) Refuse("ELF program header table overlaps the ELF header");
    const auto available = data.size() - inner;
    if (elf.ProgramOffset > available || count * ProgramHeaderSize > available - elf.ProgramOffset) Refuse("ELF program header table does not fit the file");
    for (std::size_t index = 0; index < count; ++index) {
        const auto offset = inner + elf.ProgramOffset + index * ProgramHeaderSize;
        Segment segment{index, Read<std::uint32_t>(data, offset), Read<std::uint32_t>(data, offset + 4), Read<std::uint64_t>(data, offset + 8),
                        Read<std::uint64_t>(data, offset + 16), Read<std::uint64_t>(data, offset + 32), Read<std::uint64_t>(data, offset + 40),
                        Read<std::uint64_t>(data, offset + 48), 0, std::nullopt};
        segment.Source = segment.Offset;
        if (segment.Type == PtLoad) {
            if (segment.Size > segment.Memory) Refuse("segment " + std::to_string(index) + " file size exceeds memory size");
            if (segment.Align && (segment.Align & (segment.Align - 1))) Refuse("segment " + std::to_string(index) + " alignment is not a power of two");
            if (segment.Memory > (static_cast<Wide>(1) << 64) - segment.Vaddr) Refuse("segment " + std::to_string(index) + " memory range exceeds ELF64");
        }
        elf.Segments.push_back(segment);
    }
    return elf;
}

void PlaceSegments(const std::vector<std::uint8_t>& data, std::vector<Segment>& headers, const std::vector<Record>& records) {
    const Wide length = data.size();
    std::vector<std::size_t> loads;
    for (const auto& header : headers)
        if (header.Type == PtLoad) loads.push_back(header.Index);
    std::set<std::size_t> used;
    std::set<std::size_t> placed;
    for (std::size_t index = 0; index < records.size(); ++index) {
        const auto& [flags, segment, size] = records[index];
        const auto target = flags >> RecordSegmentShift;
        if ((flags & RecordHasSegment) && target < headers.size() && !placed.contains(target) && headers[target].Size == size) {
            headers[target].Source = segment;
            placed.insert(target);
            used.insert(index);
        }
    }
    const Segment* last = nullptr;
    for (const auto& header : headers)
        if (placed.contains(header.Index) && header.Vaddr == 0 && header.Type != PtLoad && (!last || header.Offset > last->Offset)) last = &header;
    if (last) {
        Wide cursor = last->Source + last->Size;
        const auto lastOffset = last->Offset;
        std::vector<std::size_t> trailing;
        for (const auto& header : headers)
            if (!placed.contains(header.Index) && header.Vaddr == 0 && header.Type != PtLoad && header.Size && header.Offset > lastOffset) trailing.push_back(header.Index);
        std::stable_sort(trailing.begin(), trailing.end(), [&](const auto left, const auto right) { return headers[left].Offset < headers[right].Offset; });
        for (const auto index : trailing) {
            auto& header = headers[index];
            placed.insert(index);
            if (header.Type == PtNote) {
                header.Source = 0;
                header.Size = 0;
                continue;
            }
            header.Source = cursor;
            cursor += header.Size;
            if (cursor > length) {
                header.Source = 0;
                header.Size = 0;
            }
        }
    }
    for (const auto loadIndex : loads) {
        auto& header = headers[loadIndex];
        if (header.Size == 0 || placed.contains(loadIndex)) continue;
        for (std::size_t index = 0; index < records.size(); ++index) {
            if (used.contains(index)) continue;
            if (records[index].Size == header.Size) {
                used.insert(index);
                header.Source = records[index].Segment;
                break;
            }
        }
    }

    const auto loadFor = [&](const std::uint64_t vaddr, const Wide size) -> std::optional<std::size_t> {
        std::optional<std::size_t> found;
        for (const auto loadIndex : loads) {
            const auto& load = headers[loadIndex];
            const Wide end = static_cast<Wide>(load.Vaddr) + load.Memory;
            if (load.Memory && load.Vaddr <= vaddr && (vaddr < end || (size == 0 && vaddr == end))) found = loadIndex;
        }
        return found;
    };

    struct Tail {
        std::uint64_t Offset;
        Wide Shift;
    };
    std::optional<Tail> tail;
    for (auto& header : headers) {
        if (header.Type == PtLoad) continue;
        if (placed.contains(header.Index)) {
            if (const auto hostIndex = loadFor(header.Vaddr, header.Size)) {
                const auto& host = headers[*hostIndex];
                const Wide offset = header.Vaddr - host.Vaddr;
                if (host.Size && offset <= host.Size && header.Size <= host.Size - offset && header.Source == host.Source + offset) header.Host = hostIndex;
            }
            if (header.Size && (!tail || header.Offset > tail->Offset)) tail = Tail{header.Offset, header.Source - header.Offset};
            continue;
        }
        if (header.Vaddr != 0) {
            const auto hostIndex = loadFor(header.Vaddr, header.Size);
            if (!hostIndex) {
                if (header.Size == 0) {
                    header.Source = 0;
                    continue;
                }
                Refuse("segment " + std::to_string(header.Index) + " vaddr " + Hex(header.Vaddr) + " is in no PT_LOAD");
            }
            const auto& host = headers[*hostIndex];
            const Wide offset = header.Vaddr - host.Vaddr;
            if (header.Size && (offset > host.Size || header.Size > host.Size - offset))
                Refuse("segment " + std::to_string(header.Index) + " does not fit the file-backed range of PT_LOAD " + std::to_string(host.Index));
            if (host.Size == 0 || offset > host.Size) {
                header.Source = 0;
                continue;
            }
            header.Host = hostIndex;
            header.Source = host.Source + offset;
            if (!tail || header.Offset > tail->Offset) tail = Tail{header.Offset, header.Source - header.Offset};
        } else if (header.Size) {
            header.Source = header.Offset + (tail ? tail->Shift : 0);
            if (header.Source > length) header.Source = length;
            const Wide keep = std::max<Wide>(0, length - header.Source);
            header.Size = std::min(header.Size, keep);
            header.Memory = std::min(header.Memory, keep);
        }
    }

    for (const auto& header : headers) {
        if (header.Type == PtLoad && header.Size == 0) continue;
        if (header.Source < 0 || header.Source > length || header.Size > length - header.Source)
            Refuse("segment " + std::to_string(header.Index) + " does not fit the file");
    }
}

void CheckDecrypted(const std::vector<std::uint8_t>& data, const std::vector<Segment>& headers) {
    std::string listed;
    std::size_t encrypted = 0;
    std::size_t loads = 0;
    for (const auto& header : headers) {
        if (header.Type != PtLoad || header.Size == 0) continue;
        ++loads;
        const auto source = static_cast<std::uint64_t>(header.Source);
        const auto value = Entropy(data.data() + source, static_cast<std::size_t>(std::min<Wide>(header.Size, EntropySample)));
        if (value < EntropyLimit) continue;
        char bits[32];
        std::snprintf(bits, sizeof bits, "%.2f", value);
        listed += (encrypted++ ? ", " : "") + ("segment " + std::to_string(header.Index) + " at " + Hex(source) + " (" + bits + " bits per byte)");
    }
    if (encrypted && encrypted == loads) Refuse("every load segment looks encrypted: " + listed);
}

}

bool IsSelfContainer(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < 4) return false;
    const auto magic = Read<std::uint32_t>(bytes, 0);
    return magic == SelfMagic || magic == SelfMagicKernel;
}

std::vector<std::uint8_t> UnwrapSelf(const std::vector<std::uint8_t>& data, const std::uint64_t maxAlignmentPadding) {
    if (data.size() < FirstRegion) Refuse("file is smaller than the SELF header area");
    if (!IsSelfContainer(data)) Refuse("not a SELF container (magic " + Hex(Read<std::uint32_t>(data, 0)) + ")");
    const auto records = ReadRecords(data);
    auto elf = ParseElf(data);
    auto& headers = elf.Segments;
    PlaceSegments(data, headers, records);
    CheckDecrypted(data, headers);

    std::deque<Region> storage;
    std::vector<Region*> regions;
    std::vector<Region*> loadRegions(headers.size(), nullptr);
    for (const auto& header : headers) {
        if (header.Type != PtLoad || header.Size == 0) continue;
        storage.push_back({static_cast<std::uint64_t>(header.Source), static_cast<std::uint64_t>(header.Size), header.Vaddr, header.Align});
        regions.push_back(&storage.back());
        loadRegions[header.Index] = &storage.back();
    }
    const auto regionFor = [&](const std::uint64_t offset, const std::uint64_t size) -> Region* {
        for (auto* region : regions)
            if (region->Old <= offset && offset - region->Old <= region->Size && size <= region->Size - (offset - region->Old)) return region;
        return nullptr;
    };
    for (const auto& header : headers) {
        if (header.Type == PtLoad || header.Size == 0) continue;
        const auto source = static_cast<std::uint64_t>(header.Source);
        const auto size = static_cast<std::uint64_t>(header.Size);
        if (!regionFor(source, size)) {
            storage.push_back({source, size, header.Vaddr, header.Align});
            regions.push_back(&storage.back());
        }
    }
    std::stable_sort(regions.begin(), regions.end(), [](const auto* left, const auto* right) { return left->Old < right->Old; });

    const auto outputRegion = [&](const Segment& header) -> Region* {
        const auto host = header.Type == PtLoad ? std::optional<std::size_t>(header.Index) : header.Host;
        Region* region = host ? loadRegions[*host] : nullptr;
        return region ? region : regionFor(static_cast<std::uint64_t>(header.Source), static_cast<std::uint64_t>(header.Size));
    };

    for (const auto& header : headers) {
        if (header.Size == 0 && (header.Type == PtLoad || header.Source == 0)) continue;
        auto* region = outputRegion(header);
        const auto alignment = header.Align;
        if (!region || alignment <= 1 || !PowerOfTwo(alignment)) continue;
        const auto current = PowerOfTwo(region->Align) ? region->Align : 1;
        const std::uint64_t address = header.Vaddr - (static_cast<std::uint64_t>(header.Source) - region->Old);
        if ((address - region->Vaddr) % std::min(current, alignment))
            Refuse("segment " + std::to_string(header.Index) + " has incompatible alignment within its output region");
        if (alignment > current) {
            region->Align = alignment;
            region->Vaddr = address;
        }
    }

    Wide cursor = std::max<Wide>(FirstRegion, elf.ProgramOffset + headers.size() * ProgramHeaderSize);
    Wide padding = 0;
    for (auto* region : regions) {
        const auto alignment = PowerOfTwo(region->Align) ? region->Align : 1;
        const Wide placed = cursor + (region->Vaddr - static_cast<std::uint64_t>(cursor)) % alignment;
        padding += placed - cursor;
        region->New = static_cast<std::uint64_t>(placed);
        cursor = placed + region->Size;
        if (padding > maxAlignmentPadding) break;
    }
    Wide emptyEnd = cursor;
    for (const auto& header : headers)
        if (header.Type == PtLoad && header.Size == 0) emptyEnd = std::max<Wide>(emptyEnd, header.Vaddr % std::max<std::uint64_t>(header.Align, 1));
    padding += emptyEnd - cursor;
    if (padding > maxAlignmentPadding) Refuse("segment alignment requires more than " + std::to_string(maxAlignmentPadding) + " bytes of output padding");

    std::vector<std::uint8_t> result(static_cast<std::size_t>(emptyEnd));
    for (const auto* region : regions) std::memcpy(result.data() + region->New, data.data() + region->Old, region->Size);

    for (auto& header : headers) {
        if (header.Size == 0 && (header.Type == PtLoad || header.Source == 0)) {
            header.New = header.Type == PtLoad ? header.Vaddr % std::max<std::uint64_t>(header.Align, 1) : 0;
            continue;
        }
        const auto* region = outputRegion(header);
        const auto source = static_cast<std::uint64_t>(header.Source);
        header.New = region ? region->New + (source - region->Old) : source;
        if (header.New + header.Size > result.size()) Refuse("segment " + std::to_string(header.Index) + " escaped the output");
    }

    std::memcpy(result.data(), elf.Header.data(), elf.Header.size());
    Write<std::uint64_t>(result, 0x28, 0);
    Write<std::uint16_t>(result, 0x3c, 0);
    Write<std::uint16_t>(result, 0x3e, 0);
    for (const auto& header : headers) {
        const auto offset = elf.ProgramOffset + header.Index * ProgramHeaderSize;
        Write<std::uint32_t>(result, offset, header.Type);
        Write<std::uint32_t>(result, offset + 4, header.Flags);
        Write<std::uint64_t>(result, offset + 8, header.New);
        Write<std::uint64_t>(result, offset + 16, header.Vaddr);
        Write<std::uint64_t>(result, offset + 24, header.Vaddr);
        Write<std::uint64_t>(result, offset + 32, static_cast<std::uint64_t>(header.Size));
        Write<std::uint64_t>(result, offset + 40, static_cast<std::uint64_t>(header.Memory));
        Write<std::uint64_t>(result, offset + 48, header.Align);
    }
    return result;
}

}
