package rag

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
)

// Document is an input document to be chunked, embedded, and indexed.
type Document struct {
	ID       string
	Title    string
	Content  string
	Metadata map[string]string
}

// Engine implements retrieval-augmented generation for security analysis.
type Engine struct {
	embedder  *Embedder
	vectorDB  *VectorDB
	topK      int
	chunkSize int
}

// NewEngine creates a RAG engine backed by the given vector database and
// embedding model. vectorDBPath is the on-disk persistence directory.
func NewEngine(vectorDBPath, embeddingModel string, topK, chunkSize int) (*Engine, error) {
	if topK <= 0 {
		topK = 5
	}
	if chunkSize <= 0 {
		chunkSize = 512
	}

	vdb, err := NewVectorDB(vectorDBPath)
	if err != nil {
		return nil, err
	}

	embedder := NewEmbedder(EmbedLocal, "", embeddingModel, 512)

	return &Engine{
		embedder:  embedder,
		vectorDB:  vdb,
		topK:      topK,
		chunkSize: chunkSize,
	}, nil
}

// Query embeds the input text and retrieves the top-K most relevant knowledge
// chunks from the vector store.
func (e *Engine) Query(ctx context.Context, text string) ([]Chunk, error) {
	embedding, err := e.embedder.Embed(ctx, text)
	if err != nil {
		return nil, fmt.Errorf("rag query: %w", err)
	}
	return e.vectorDB.Query(ctx, embedding, e.topK)
}

// IndexDocument chunks, embeds, and stores a document in the vector database.
func (e *Engine) IndexDocument(ctx context.Context, doc Document) error {
	chunks := e.chunk(doc.Content)
	for i, chunk := range chunks {
		e.embedder.TrainLocal(chunk)
		embedding, err := e.embedder.Embed(ctx, chunk)
		if err != nil {
			return fmt.Errorf("rag index: %w", err)
		}

		meta := make(map[string]string)
		for k, v := range doc.Metadata {
			meta[k] = v
		}
		meta["source"] = doc.Title
		meta["chunk_index"] = fmt.Sprintf("%d", i)

		id := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%d", doc.ID, i))))
		if err := e.vectorDB.Add(ctx, id, chunk, embedding, meta); err != nil {
			return err
		}
	}
	return nil
}

// IndexKnowledgeBase indexes a well-known knowledge base (e.g. "mitre_attack",
// "sigma_rules") by name. The content is loaded from built-in data.
func (e *Engine) IndexKnowledgeBase(ctx context.Context, name string) error {
	kb, ok := knowledgeBases[name]
	if !ok {
		return fmt.Errorf("rag: unknown knowledge base %q", name)
	}
	for _, entry := range kb {
		doc := Document{
			ID:      fmt.Sprintf("%s:%s", name, entry.id),
			Title:   entry.title,
			Content: entry.content,
			Metadata: map[string]string{
				"knowledge_base": name,
				"category":       entry.category,
			},
		}
		if err := e.IndexDocument(ctx, doc); err != nil {
			return err
		}
	}
	return nil
}

// Close releases all resources held by the RAG engine.
func (e *Engine) Close() error {
	return e.vectorDB.Close()
}

func (e *Engine) chunk(text string) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var chunks []string
	for i := 0; i < len(words); i += e.chunkSize {
		end := i + e.chunkSize
		if end > len(words) {
			end = len(words)
		}
		chunks = append(chunks, strings.Join(words[i:end], " "))
	}
	return chunks
}

type kbEntry struct {
	id       string
	title    string
	category string
	content  string
}

var knowledgeBases = map[string][]kbEntry{
	"mitre_attack": {
		{id: "T1059", title: "Command and Scripting Interpreter", category: "execution",
			content: "T1059 - Command and Scripting Interpreter. Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. Sub-techniques include PowerShell (T1059.001), AppleScript (T1059.002), Windows Command Shell (T1059.003), Unix Shell (T1059.004), Visual Basic (T1059.005), Python (T1059.006), JavaScript (T1059.007)."},
		{id: "T1055", title: "Process Injection", category: "defense_evasion",
			content: "T1055 - Process Injection. Adversaries may inject code into processes to evade defenses and elevate privileges. Sub-techniques include DLL Injection (T1055.001), PE Injection (T1055.002), Thread Execution Hijacking (T1055.003), Ptrace System Calls (T1055.008), Process Hollowing (T1055.012)."},
		{id: "T1547", title: "Boot or Logon Autostart Execution", category: "persistence",
			content: "T1547 - Boot or Logon Autostart Execution. Adversaries may configure system settings to automatically execute a program during boot or logon. Sub-techniques include Registry Run Keys (T1547.001), Authentication Package (T1547.002), Kernel Modules (T1547.006), Plist Modification (T1547.011)."},
		{id: "T1071", title: "Application Layer Protocol", category: "command_and_control",
			content: "T1071 - Application Layer Protocol. Adversaries may communicate using OSI application layer protocols to avoid detection. Sub-techniques include Web Protocols (T1071.001), File Transfer Protocols (T1071.002), Mail Protocols (T1071.003), DNS (T1071.004)."},
		{id: "T1486", title: "Data Encrypted for Impact", category: "impact",
			content: "T1486 - Data Encrypted for Impact. Adversaries may encrypt data on target systems to interrupt availability. This is commonly associated with ransomware. May target local storage, network shares, and cloud storage."},
		{id: "T1003", title: "OS Credential Dumping", category: "credential_access",
			content: "T1003 - OS Credential Dumping. Adversaries may attempt to dump credentials to obtain account login and credential material. Sub-techniques include LSASS Memory (T1003.001), SAM (T1003.002), NTDS (T1003.003), LSA Secrets (T1003.004), /etc/passwd and /etc/shadow (T1003.008)."},
		{id: "T1048", title: "Exfiltration Over Alternative Protocol", category: "exfiltration",
			content: "T1048 - Exfiltration Over Alternative Protocol. Adversaries may steal data by exfiltrating it over a different protocol than the existing command and control channel. Sub-techniques include Exfiltration Over Symmetric Encrypted Non-C2 Protocol (T1048.001), Asymmetric (T1048.002), Unencrypted (T1048.003)."},
		{id: "T1190", title: "Exploit Public-Facing Application", category: "initial_access",
			content: "T1190 - Exploit Public-Facing Application. Adversaries may attempt to exploit a weakness in an Internet-facing host or resource. Common targets include web servers, database servers, and edge network infrastructure."},
	},
	"sigma_rules": {
		{id: "proc_creation_win_susp_powershell", title: "Suspicious PowerShell Command Line", category: "process_creation",
			content: "Detects suspicious PowerShell command line arguments including encoded commands (-enc, -encodedcommand), download cradles (IEX, Invoke-Expression, downloadstring, Net.WebClient), and execution policy bypass (-ep bypass, -executionpolicy bypass)."},
		{id: "proc_creation_win_susp_certutil", title: "Suspicious Certutil Usage", category: "process_creation",
			content: "Detects suspicious use of certutil.exe for downloading files (-urlcache -split -f), encoding/decoding (-encode, -decode), and hash computation. Often abused as a living-off-the-land binary (LOLBin)."},
		{id: "file_event_win_creation_susp_locations", title: "File Creation in Suspicious Locations", category: "file_event",
			content: "Detects file creation in suspicious locations such as C:\\ProgramData, C:\\Users\\Public, temp directories, and recycle bin. These locations are commonly used by malware for staging and persistence."},
	},
}
