package protofixture

import "fmt"

// Case is one protocol, scenario and stream combination of the catalogue.
type Case struct {
	Protocol Protocol
	Scenario Scenario
	Stream   bool
}

func (value Case) String() string {
	mode := "json"
	if value.Stream {
		mode = "sse"
	}
	return fmt.Sprintf("%s/%s/%s", value.Protocol, value.Scenario, mode)
}

// Catalog lists every supported case: all scenarios for all protocols, in
// both modes, except that broken-stream scenarios exist only when streaming.
func Catalog() []Case {
	cases := make([]Case, 0, 128)
	scenarios := append(NormalScenarios(), AbnormalScenarios()...)
	for _, protocol := range Protocols() {
		for _, stream := range []bool{false, true} {
			for _, scenario := range scenarios {
				if scenario.StreamOnly() && !stream {
					continue
				}
				cases = append(cases, Case{Protocol: protocol, Scenario: scenario, Stream: stream})
			}
		}
	}
	return cases
}

// Build generates the exchanges of one named scenario. Most scenarios yield
// one exchange; multi_turn yields three successive turns, branch yields two
// turns and then two different continuations of them, and tool_calls yields
// the turn that calls tools and the turn that returns their results.
func Build(value Case, options Options) ([]Exchange, error) {
	conversation := NewConversation(value.Protocol, value.Stream, options, int(options.Seed%1000))
	switch value.Scenario {
	case ScenarioBasic:
		return []Exchange{conversation.Next(value.Scenario, Features{})}, nil
	case ScenarioMultiTurn:
		return []Exchange{
			conversation.Next(value.Scenario, Features{}),
			conversation.Next(value.Scenario, Features{}),
			conversation.Next(value.Scenario, Features{}),
		}, nil
	case ScenarioBranch:
		first := conversation.Next(value.Scenario, Features{})
		second := conversation.Next(value.Scenario, Features{})
		fork := conversation.Fork()
		return []Exchange{first, second, conversation.Next(value.Scenario, Features{}), fork.Next(value.Scenario, Features{})}, nil
	case ScenarioToolCalls:
		calls := conversation.Next(value.Scenario, Features{Tools: true, ParallelTools: true})
		results := conversation.Next(value.Scenario, Features{})
		return []Exchange{calls, results}, nil
	case ScenarioMultimodal:
		return []Exchange{conversation.Next(value.Scenario, Features{Image: true})}, nil
	case ScenarioReasoning:
		return []Exchange{conversation.Next(value.Scenario, Features{Reasoning: true, Citations: true})}, nil
	case ScenarioUsageShapes:
		return []Exchange{conversation.Next(value.Scenario, Features{UsageShapes: true, Reasoning: true})}, nil
	case ScenarioExtensions:
		return []Exchange{conversation.Next(value.Scenario, Features{Extensions: true, Reasoning: true, Tools: true})}, nil
	case ScenarioMixed:
		return []Exchange{conversation.Next(value.Scenario, conversation.MixedFeatures())}, nil
	default:
		// Abnormal answers replay a later turn so the request has history.
		conversation.Next(ScenarioBasic, Features{})
		exchange, err := conversation.Abnormal(value.Scenario)
		if err != nil {
			return nil, err
		}
		return []Exchange{exchange}, nil
	}
}
