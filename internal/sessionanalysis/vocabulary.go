// Package sessionanalysis turns audited sessions into deterministic signals,
// compact input packs for a local model, per-session facets and periodic
// summaries (doc/features/24-session-analysis.md).
//
// Plaintext output is limited to counts, enums, model names and keyed
// fingerprints. Message text, commands and paths only leave the package inside
// values the caller encrypts before storage.
package sessionanalysis

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed vocabulary_default.yaml
var defaultVocabularyYAML []byte

// VocabularyFile is the YAML shape of the vocabulary and its override file.
type VocabularyFile struct {
	ShellWrappers             []string            `yaml:"shell_wrappers"`
	ShellInterpreters         []string            `yaml:"shell_interpreters"`
	ShellClasses              []ShellClass        `yaml:"shell_classes"`
	DangerPatterns            map[string][]string `yaml:"danger_patterns"`
	SecretPatterns            map[string][]string `yaml:"secret_patterns"`
	ContactPatterns           []string            `yaml:"contact_patterns"`
	CorrectionPrefixes        []string            `yaml:"correction_prefixes"`
	CorrectionPhrases         []string            `yaml:"correction_phrases"`
	ErrorPatterns             []string            `yaml:"error_patterns"`
	InterruptMarkers          []string            `yaml:"interrupt_markers"`
	CompactionSummaryPrefixes []string            `yaml:"compaction_summary_prefixes"`
	ExitCodePatterns          []string            `yaml:"exit_code_patterns"`
	FailurePhrases            []string            `yaml:"failure_phrases"`
	ToolClasses               map[string][]string `yaml:"tool_classes"`
	HeavyModels               []string            `yaml:"heavy_models"`
	HeavyMaxOutputTokens      int64               `yaml:"heavy_max_output_tokens"`
	HeavyMaxToolCalls         int64               `yaml:"heavy_max_tool_calls"`
	LoopMinRepeats            int                 `yaml:"loop_min_repeats"`
	ThrashMinWrites           int                 `yaml:"thrash_min_writes"`
}

// ShellClass is one ordered shell command class.
type ShellClass struct {
	Class    string   `yaml:"class"`
	Commands []string `yaml:"commands"`
}

// Vocabulary is the compiled vocabulary.
type Vocabulary struct {
	wrappers          map[string]bool
	interpreters      map[string]bool
	classes           []ShellClass
	danger            []namedPatterns
	secrets           []namedPatterns
	contacts          []*regexp.Regexp
	correctionPrefix  []string
	correctionPhrases []string
	errors            []*regexp.Regexp
	interrupts        []string
	summaryPrefixes   []string
	exitCodes         []*regexp.Regexp
	failurePhrases    []string
	toolClasses       map[string]string
	heavyModels       []string
	heavyMaxOutput    int64
	heavyMaxTools     int64
	loopMinRepeats    int
	thrashMinWrites   int
}

type namedPatterns struct {
	name     string
	patterns []*regexp.Regexp
}

var knownShellClasses = map[string]bool{"test": true, "lint": true, "build": true, "pkg": true, "read": true, "search": true, "git": true, "run": true}

var knownToolClasses = map[string]bool{"web": true, "plan": true}

var categoryName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// DefaultVocabulary returns the compiled built-in vocabulary.
func DefaultVocabulary() *Vocabulary {
	vocab, err := LoadVocabulary("")
	if err != nil {
		panic("sessionanalysis: invalid embedded vocabulary: " + err.Error())
	}
	return vocab
}

// LoadVocabulary compiles the built-in vocabulary merged with the optional
// override file at path.
func LoadVocabulary(path string) (*Vocabulary, error) {
	base, err := parseVocabularyFile(defaultVocabularyYAML)
	if err != nil {
		return nil, fmt.Errorf("session analysis vocabulary: %w", err)
	}
	if strings.TrimSpace(path) != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("session analysis vocabulary: %w", err)
		}
		override, err := parseVocabularyFile(data)
		if err != nil {
			return nil, fmt.Errorf("session analysis vocabulary: %w", err)
		}
		base.merge(override)
	}
	vocab, err := base.compile()
	if err != nil {
		return nil, fmt.Errorf("session analysis vocabulary: %w", err)
	}
	return vocab, nil
}

func parseVocabularyFile(data []byte) (VocabularyFile, error) {
	var file VocabularyFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		if errors.Is(err, io.EOF) {
			return file, nil
		}
		return VocabularyFile{}, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple YAML documents are not supported")
		}
		return VocabularyFile{}, err
	}
	return file, nil
}

func (file *VocabularyFile) merge(override VocabularyFile) {
	replace := func(target *[]string, value []string) {
		if value != nil {
			*target = value
		}
	}
	replace(&file.ShellWrappers, override.ShellWrappers)
	replace(&file.ShellInterpreters, override.ShellInterpreters)
	if override.ShellClasses != nil {
		file.ShellClasses = override.ShellClasses
	}
	file.DangerPatterns = mergeLists(file.DangerPatterns, override.DangerPatterns)
	file.SecretPatterns = mergeLists(file.SecretPatterns, override.SecretPatterns)
	replace(&file.ContactPatterns, override.ContactPatterns)
	replace(&file.CorrectionPrefixes, override.CorrectionPrefixes)
	replace(&file.CorrectionPhrases, override.CorrectionPhrases)
	replace(&file.ErrorPatterns, override.ErrorPatterns)
	replace(&file.InterruptMarkers, override.InterruptMarkers)
	replace(&file.CompactionSummaryPrefixes, override.CompactionSummaryPrefixes)
	replace(&file.ExitCodePatterns, override.ExitCodePatterns)
	replace(&file.FailurePhrases, override.FailurePhrases)
	file.ToolClasses = mergeLists(file.ToolClasses, override.ToolClasses)
	replace(&file.HeavyModels, override.HeavyModels)
	if override.HeavyMaxOutputTokens != 0 {
		file.HeavyMaxOutputTokens = override.HeavyMaxOutputTokens
	}
	if override.HeavyMaxToolCalls != 0 {
		file.HeavyMaxToolCalls = override.HeavyMaxToolCalls
	}
	if override.LoopMinRepeats != 0 {
		file.LoopMinRepeats = override.LoopMinRepeats
	}
	if override.ThrashMinWrites != 0 {
		file.ThrashMinWrites = override.ThrashMinWrites
	}
}

func mergeLists(base, override map[string][]string) map[string][]string {
	if base == nil {
		base = map[string][]string{}
	}
	for key, value := range override {
		base[key] = value
	}
	return base
}

func lowerAll(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		// Inner and trailing spaces are significant ("no " is not "no,").
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.ToLower(strings.TrimLeft(value, " \t")))
		}
	}
	return out
}

func compilePatterns(field string, patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) == "" {
			return nil, fmt.Errorf("%s contains an empty pattern", field)
		}
		compiled, err := regexp.Compile("(?im)" + pattern)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		out = append(out, compiled)
	}
	return out, nil
}

func compileNamed(field string, groups map[string][]string) ([]namedPatterns, error) {
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]namedPatterns, 0, len(names))
	for _, name := range names {
		if !categoryName.MatchString(name) {
			return nil, fmt.Errorf("%s: invalid category name %q", field, name)
		}
		if len(groups[name]) == 0 {
			continue // an override may switch a category off with an empty list
		}
		patterns, err := compilePatterns(field+"."+name, groups[name])
		if err != nil {
			return nil, err
		}
		out = append(out, namedPatterns{name: name, patterns: patterns})
	}
	return out, nil
}

func (file VocabularyFile) compile() (*Vocabulary, error) {
	vocab := &Vocabulary{
		wrappers:          map[string]bool{},
		interpreters:      map[string]bool{},
		correctionPrefix:  lowerAll(file.CorrectionPrefixes),
		correctionPhrases: lowerAll(file.CorrectionPhrases),
		interrupts:        lowerAll(file.InterruptMarkers),
		summaryPrefixes:   lowerAll(file.CompactionSummaryPrefixes),
		failurePhrases:    lowerAll(file.FailurePhrases),
		toolClasses:       map[string]string{},
		heavyModels:       lowerAll(file.HeavyModels),
		heavyMaxOutput:    file.HeavyMaxOutputTokens,
		heavyMaxTools:     file.HeavyMaxToolCalls,
		loopMinRepeats:    file.LoopMinRepeats,
		thrashMinWrites:   file.ThrashMinWrites,
	}
	for _, word := range file.ShellWrappers {
		vocab.wrappers[strings.ToLower(strings.TrimSpace(word))] = true
	}
	for _, word := range file.ShellInterpreters {
		vocab.interpreters[strings.ToLower(strings.TrimSpace(word))] = true
	}
	for _, class := range file.ShellClasses {
		if !knownShellClasses[class.Class] {
			return nil, fmt.Errorf("shell_classes: unknown class %q", class.Class)
		}
		commands := make([]string, 0, len(class.Commands))
		for _, command := range class.Commands {
			normalized := strings.Join(strings.Fields(strings.ToLower(command)), " ")
			if normalized == "" {
				return nil, fmt.Errorf("shell_classes.%s contains an empty command", class.Class)
			}
			commands = append(commands, normalized)
		}
		vocab.classes = append(vocab.classes, ShellClass{Class: class.Class, Commands: commands})
	}
	var err error
	if vocab.danger, err = compileNamed("danger_patterns", file.DangerPatterns); err != nil {
		return nil, err
	}
	if vocab.secrets, err = compileNamed("secret_patterns", file.SecretPatterns); err != nil {
		return nil, err
	}
	if vocab.contacts, err = compilePatterns("contact_patterns", file.ContactPatterns); err != nil {
		return nil, err
	}
	if vocab.errors, err = compilePatterns("error_patterns", file.ErrorPatterns); err != nil {
		return nil, err
	}
	if vocab.exitCodes, err = compilePatterns("exit_code_patterns", file.ExitCodePatterns); err != nil {
		return nil, err
	}
	for _, pattern := range vocab.exitCodes {
		if pattern.NumSubexp() < 1 {
			return nil, errors.New("exit_code_patterns entries need a capture group for the code")
		}
	}
	for class, tools := range file.ToolClasses {
		if !knownToolClasses[class] {
			return nil, fmt.Errorf("tool_classes: unknown class %q", class)
		}
		for _, tool := range tools {
			vocab.toolClasses[strings.ToLower(strings.TrimSpace(tool))] = class
		}
	}
	if vocab.heavyMaxOutput < 0 || vocab.heavyMaxTools < 0 {
		return nil, errors.New("heavy model limits must not be negative")
	}
	if vocab.loopMinRepeats < 2 {
		return nil, errors.New("loop_min_repeats must be at least 2")
	}
	if vocab.thrashMinWrites < 2 {
		return nil, errors.New("thrash_min_writes must be at least 2")
	}
	return vocab, nil
}
