package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SystemPrompt instructs the LLM to behave as a senior SOC analyst performing
// structured security-event triage.
const SystemPrompt = `You are a Senior Security Operations Center (SOC) analyst with 15+ years of experience in threat detection, incident response, and malware analysis. You are integrated into an Endpoint Detection and Response (EDR) agent and your role is to analyze security events in real time.

For every event you receive, you MUST:

1. CLASSIFY the event as benign or malicious. Consider the full process tree, file operations, network connections, and registry changes provided in the context.
2. MAP to MITRE ATT&CK: Identify all applicable Technique IDs (e.g., T1059.001) and their parent Tactics.
3. ASSESS FALSE-POSITIVE RISK: Rate as "low", "medium", or "high" with justification. Common developer tools, system updates, and package managers are frequent false-positive sources.
4. DETERMINE SEVERITY: Use "info", "low", "medium", "high", or "critical" based on potential impact.
5. RECOMMEND an action: One of "allow", "alert", "isolate", "kill_process", "quarantine_file", or "block_network".
6. EXTRACT IOCs: List any suspicious IPs, domains, hashes, file paths, or registry keys.

You MUST respond with ONLY a valid JSON object matching this exact schema — no markdown fences, no commentary:
{
  "threat_detected": bool,
  "confidence": float between 0.0 and 1.0,
  "threat_type": "string describing the threat category",
  "severity": "info|low|medium|high|critical",
  "mitre_techniques": ["T1234.001", ...],
  "reasoning": "detailed explanation of your analysis",
  "recommended_action": "allow|alert|isolate|kill_process|quarantine_file|block_network",
  "iocs": ["indicator1", ...],
  "false_positive_risk": "low|medium|high",
  "analyst_notes": "additional context or caveats"
}`

// BuildAnalysisPrompt constructs a structured prompt from the event context
// suitable for submission to any LLM provider.
func BuildAnalysisPrompt(ctx *EventContext) string {
	var b strings.Builder
	b.WriteString("Analyze the following security event and its surrounding context.\n\n")

	if ctx.Event != nil {
		raw, err := json.Marshal(ctx.Event)
		if err == nil {
			b.WriteString("## Event\n```json\n")
			b.Write(raw)
			b.WriteString("\n```\n\n")
		}
	}

	if len(ctx.ProcessTree) > 0 {
		b.WriteString("## Process Tree\n")
		for _, p := range ctx.ProcessTree {
			fmt.Fprintf(&b, "- PID=%d PPID=%d Name=%s Path=%s Args=%q User=%s\n",
				p.PID, p.PPID, p.Name, p.Path, p.Args, p.User)
		}
		b.WriteString("\n")
	}

	if len(ctx.RecentFiles) > 0 {
		b.WriteString("## Recent File Operations\n")
		for _, f := range ctx.RecentFiles {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		b.WriteString("\n")
	}

	if len(ctx.RecentConnections) > 0 {
		b.WriteString("## Recent Network Connections\n")
		for _, c := range ctx.RecentConnections {
			fmt.Fprintf(&b, "- %s\n", c)
		}
		b.WriteString("\n")
	}

	if len(ctx.RecentRegistryChanges) > 0 {
		b.WriteString("## Recent Registry Changes\n")
		for _, r := range ctx.RecentRegistryChanges {
			fmt.Fprintf(&b, "- %s\n", r)
		}
		b.WriteString("\n")
	}

	if len(ctx.SimilarHistorical) > 0 {
		b.WriteString("## Similar Historical Events\n")
		for _, h := range ctx.SimilarHistorical {
			raw, err := json.Marshal(h)
			if err == nil {
				b.WriteString("- ")
				b.Write(raw)
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}

	if len(ctx.ThreatIntelContext) > 0 {
		b.WriteString("## Threat Intelligence\n")
		for _, t := range ctx.ThreatIntelContext {
			fmt.Fprintf(&b, "- %s\n", t)
		}
		b.WriteString("\n")
	}

	if len(ctx.BehavioralIndicators) > 0 {
		b.WriteString("## Behavioral Detection Results\n")
		b.WriteString("The following detections already fired for this event from rule/ML/behavioral layers:\n")
		for _, bi := range ctx.BehavioralIndicators {
			fmt.Fprintf(&b, "- %s\n", bi)
		}
		b.WriteString("\n")
	}

	b.WriteString("Respond with the JSON verdict only.")
	return b.String()
}

// ParseVerdict extracts a Verdict from the raw LLM JSON response.
func ParseVerdict(response string) (*Verdict, error) {
	response = strings.TrimSpace(response)
	// Strip optional markdown code fences that some models emit.
	if strings.HasPrefix(response, "```") {
		lines := strings.SplitN(response, "\n", 2)
		if len(lines) == 2 {
			response = lines[1]
		}
		if idx := strings.LastIndex(response, "```"); idx >= 0 {
			response = response[:idx]
		}
		response = strings.TrimSpace(response)
	}

	var v Verdict
	if err := json.Unmarshal([]byte(response), &v); err != nil {
		return nil, fmt.Errorf("llm: failed to parse verdict: %w (raw: %.512s)", err, response)
	}
	if v.Confidence < 0 || v.Confidence > 1 {
		return nil, fmt.Errorf("llm: confidence %.2f out of [0,1] range", v.Confidence)
	}
	return &v, nil
}
