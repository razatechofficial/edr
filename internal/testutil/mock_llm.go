package testutil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
)

// MockLLMServer creates an HTTP test server that mimics an LLM API.
// The responses map keys are matched against the request URL path.
func MockLLMServer(responses map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := responses[r.URL.Path]
		if !ok {
			body = responses["default"]
			if body == "" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
}

// MockOpenAIResponse returns a valid OpenAI chat completion API response body.
func MockOpenAIResponse(content string) string {
	resp := map[string]interface{}{
		"id":      "chatcmpl-test",
		"object":  "chat.completion",
		"created": 1700000000,
		"model":   "gpt-4",
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": content,
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]interface{}{
			"prompt_tokens":     10,
			"completion_tokens": 20,
			"total_tokens":      30,
		},
	}
	data, _ := json.Marshal(resp)
	return string(data)
}
