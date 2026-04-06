package features

import (
	"bufio"
	"debug/pe"
	"io"
	"math"
	"os"
	"time"
)

const (
	byteHistogramSize  = 256
	entropyBins        = 16
	maxSections        = 16
	stringFeatureCount = 8
	peFeatureCount     = 8
	formatFeatureCount = 3
	headerFeatureCount = 2
	baseFeatureCount   = 2 // whole-file entropy + file size (log)

	// TotalFileFeatures is the output dimensionality of Extract: 311.
	TotalFileFeatures = byteHistogramSize + entropyBins + baseFeatureCount +
		stringFeatureCount + peFeatureCount + maxSections +
		formatFeatureCount + headerFeatureCount

	streamChunkSize = 32 * 1024
	maxScanBytes    = 100 * 1024 * 1024 // 100 MB cap
	maxSectionBytes = 1024 * 1024       // 1 MB per section for entropy
)

// PEFeatureExtractor extracts features from executable files for malware
// classification, inspired by the EMBER dataset feature set.
type PEFeatureExtractor struct{}

// Extract reads the file at path in a streaming fashion and returns a
// TotalFileFeatures-dimensional feature vector. PE files receive additional
// header-derived features; other formats use general features only.
func (e *PEFeatureExtractor) Extract(path string) ([]float32, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := info.Size()
	scanLimit := fileSize
	if scanLimit > maxScanBytes {
		scanLimit = maxScanBytes
	}

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var (
		byteCounts     [256]uint64
		totalBytes     uint64
		chunkEntropies []float64
		strStats       stringStats
	)

	rd := bufio.NewReaderSize(f, streamChunkSize)
	chunk := make([]byte, streamChunkSize)

	for totalBytes < uint64(scanLimit) {
		n, readErr := rd.Read(chunk)
		if n > 0 {
			block := chunk[:n]
			for _, b := range block {
				byteCounts[b]++
			}
			totalBytes += uint64(n)
			chunkEntropies = append(chunkEntropies, shannonEntropy(block))
			scanStrings(&strStats, block)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}

	feats := make([]float32, TotalFileFeatures)
	idx := 0

	// Byte histogram (normalized).
	for i := 0; i < byteHistogramSize; i++ {
		if totalBytes > 0 {
			feats[idx] = float32(float64(byteCounts[i]) / float64(totalBytes))
		}
		idx++
	}

	// Chunk entropy histogram.
	writeEntropyHistogram(feats[idx:idx+entropyBins], chunkEntropies)
	idx += entropyBins

	// Whole-file entropy.
	feats[idx] = float32(wholeFileEntropy(byteCounts[:], totalBytes))
	idx++

	// File size (log-scaled).
	feats[idx] = float32(math.Log1p(float64(fileSize)))
	idx++

	// String features (log-scaled counts and statistics).
	feats[idx+0] = float32(math.Log1p(float64(strStats.urlCount)))
	feats[idx+1] = float32(math.Log1p(float64(strStats.ipCount)))
	feats[idx+2] = float32(math.Log1p(float64(strStats.registryCount)))
	feats[idx+3] = float32(math.Log1p(float64(strStats.pathCount)))
	feats[idx+4] = float32(math.Log1p(float64(strStats.base64Count)))
	feats[idx+5] = float32(math.Log1p(float64(strStats.totalStrings)))
	if strStats.totalStrings > 0 {
		feats[idx+6] = float32(strStats.avgLength)
	}
	feats[idx+7] = NormalizeMinMax(strStats.maxLength, 0, 1000)
	idx += stringFeatureCount

	peStart := idx
	idx += peFeatureCount

	sectionStart := idx
	idx += maxSections

	formatStart := idx
	idx += formatFeatureCount

	headerStart := idx

	format := detectMagic(magic[:])
	switch format {
	case formatPE:
		feats[formatStart] = 1.0
		if pf, peErr := pe.NewFile(f); peErr == nil {
			populatePEFeatures(feats, peStart, sectionStart, headerStart, pf)
			pf.Close()
		}
	case formatELF:
		feats[formatStart+1] = 1.0
	case formatMachO:
		feats[formatStart+2] = 1.0
	}

	return feats, nil
}

// FeatureCount returns the total dimensionality of the file feature vector.
func (e *PEFeatureExtractor) FeatureCount() int { return TotalFileFeatures }

// --- internal helpers ---

type stringStats struct {
	urlCount      int
	ipCount       int
	registryCount int
	pathCount     int
	base64Count   int
	totalStrings  int
	avgLength     float64
	maxLength     float64
	lengthSum     float64
}

func scanStrings(stats *stringStats, data []byte) {
	var (
		inStr  bool
		strLen int
	)
	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			if !inStr {
				inStr = true
				strLen = 0
			}
			strLen++
		} else {
			if inStr && strLen >= 4 {
				stats.totalStrings++
				stats.lengthSum += float64(strLen)
				if float64(strLen) > stats.maxLength {
					stats.maxLength = float64(strLen)
				}
			}
			inStr = false
			strLen = 0
		}
	}

	end := len(data) - 4
	for i := 0; i < end; i++ {
		switch {
		case data[i] == 'h' && data[i+1] == 't' && data[i+2] == 't' && data[i+3] == 'p':
			stats.urlCount++
			i += 3
		case isDigit(data[i]) && data[i+1] == '.' && isDigit(data[i+2]) && data[i+3] == '.':
			stats.ipCount++
			i += 3
		case data[i] == 'H' && data[i+1] == 'K' &&
			(data[i+2] == 'E' || data[i+2] == 'L' || data[i+2] == 'C' || data[i+2] == 'U'):
			stats.registryCount++
			i += 2
		case (data[i] == '/' || data[i] == '\\') && isAlpha(data[i+1]):
			stats.pathCount++
		case data[i] == '=' && i > 0 && isBase64Char(data[i-1]):
			stats.base64Count++
		}
	}

	if stats.totalStrings > 0 {
		stats.avgLength = stats.lengthSum / float64(stats.totalStrings)
	}
}

func isDigit(b byte) bool     { return b >= '0' && b <= '9' }
func isAlpha(b byte) bool     { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') }
func isBase64Char(b byte) bool { return isAlpha(b) || isDigit(b) || b == '+' || b == '/' }

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func wholeFileEntropy(counts []uint64, total uint64) float64 {
	if total == 0 {
		return 0
	}
	n := float64(total)
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func writeEntropyHistogram(dst []float32, entropies []float64) {
	if len(entropies) == 0 {
		return
	}
	bins := len(dst)
	for _, e := range entropies {
		bin := int(e * float64(bins) / 8.0)
		if bin >= bins {
			bin = bins - 1
		}
		if bin < 0 {
			bin = 0
		}
		dst[bin]++
	}
	inv := 1.0 / float32(len(entropies))
	for i := range dst {
		dst[i] *= inv
	}
}

type fileFormat int

const (
	formatUnknown fileFormat = iota
	formatPE
	formatELF
	formatMachO
)

func detectMagic(header []byte) fileFormat {
	if len(header) < 4 {
		return formatUnknown
	}
	switch {
	case header[0] == 'M' && header[1] == 'Z':
		return formatPE
	case header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F':
		return formatELF
	case header[0] == 0xfe && header[1] == 0xed && header[2] == 0xfa && header[3] == 0xce,
		header[0] == 0xcf && header[1] == 0xfa && header[2] == 0xed && header[3] == 0xfe,
		header[0] == 0xca && header[1] == 0xfe && header[2] == 0xba && header[3] == 0xbe:
		return formatMachO
	default:
		return formatUnknown
	}
}

func populatePEFeatures(feats []float32, peStart, sectionStart, headerStart int, pf *pe.File) {
	feats[peStart] = float32(len(pf.Sections))

	imports, _ := pf.ImportedSymbols()
	feats[peStart+1] = float32(math.Log1p(float64(len(imports))))

	var hasExports, hasSignature, hasDebug float32
	var imageSize uint32

	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd := oh.DataDirectory
		if dd[0].Size > 0 {
			hasExports = 1.0
		}
		if dd[4].Size > 0 {
			hasSignature = 1.0
		}
		if dd[6].Size > 0 {
			hasDebug = 1.0
		}
		imageSize = oh.SizeOfImage
	case *pe.OptionalHeader64:
		dd := oh.DataDirectory
		if dd[0].Size > 0 {
			hasExports = 1.0
		}
		if dd[4].Size > 0 {
			hasSignature = 1.0
		}
		if dd[6].Size > 0 {
			hasDebug = 1.0
		}
		imageSize = oh.SizeOfImage
	}

	feats[peStart+2] = hasExports
	feats[peStart+3] = hasSignature
	feats[peStart+4] = hasDebug

	compileTime := time.Unix(int64(pf.FileHeader.TimeDateStamp), 0)
	ageYears := time.Since(compileTime).Hours() / (24.0 * 365.0)
	feats[peStart+5] = float32(math.Log1p(math.Abs(ageYears)))

	// Per-section entropy (normalized to [0,1]).
	n := min(len(pf.Sections), maxSections)
	for i := 0; i < n; i++ {
		data, err := pf.Sections[i].Data()
		if err != nil || len(data) == 0 {
			continue
		}
		if len(data) > maxSectionBytes {
			data = data[:maxSectionBytes]
		}
		feats[sectionStart+i] = float32(shannonEntropy(data) / 8.0)
	}

	if n > 0 {
		var sum float32
		for i := 0; i < n; i++ {
			sum += feats[sectionStart+i]
		}
		feats[peStart+6] = sum / float32(n)
	}
	if len(pf.Sections) > 0 {
		feats[peStart+7] = feats[sectionStart]
	}

	feats[headerStart] = float32(math.Log1p(float64(imageSize)))

	var totalRaw, totalVirtual uint32
	for _, sec := range pf.Sections {
		totalRaw += sec.Size
		totalVirtual += sec.VirtualSize
	}
	if totalRaw > 0 {
		feats[headerStart+1] = float32(float64(totalVirtual) / float64(totalRaw))
	}
}
