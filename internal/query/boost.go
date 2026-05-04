package query

import (
	"math"
	"strings"

	"github.com/cloudprivacylabs/lpg/v2"

	"github.com/realxen/cartograph/internal/graph"
	"github.com/realxen/cartograph/internal/search"
	"github.com/realxen/cartograph/internal/service"
)

// Domain trigger terms.
// Query text is checked against these to decide which domain rules apply.
var (
	httpTriggers     = []string{"handler", "http", "route", "endpoint", "api", "controller", "servlet", "middleware"}
	dbTriggers       = []string{"database", "model", "schema", "migration", "repository", "store", "dao", "orm", "query"}
	configTriggers   = []string{"config", "configuration", "setting", "environment", "env", "builder", "build", "configurer", "customizer", "bean", "parser", "wire", "httpsecurity", "websecurity"}
	securityTriggers = []string{"auth", "authentication", "authorization", "security", "login", "logout", "token", "credential", "permission", "access", "advisor", "interceptor"}
)

// HTTP / handler / routing domain signals.
var (
	httpPathSignals = []string{
		"handler", "server", "route", "controller",
		"view", "middleware", "endpoint", "api", "servlet",
		"resource", "url", "router", "startup", "httpd",
	}

	httpNamePrefixes = []string{
		"handle", "serve", "register", "route",
		"dispatch", "respond", "controller", "endpoint",
		"configure", "map", "action", "do_", "doget", "dopost",
	}

	httpNameSuffixes = []string{
		"controller", "servlet", "resource",
		"handler", "view", "viewset", "middleware", "mapping",
		"endpoint", "router",
	}
)

// Database / model / repository domain signals.
var (
	dbPathSignals = []string{
		"model", "schema", "migration", "repositor",
		"store", "dao", "entit", "database", "db", "persist",
	}
	dbNamePrefixes = []string{
		"model", "schema", "migrat", "repositor",
		"store", "dao", "entity", "record", "table",
	}
	dbNameSuffixes = []string{
		"model", "schema", "repository",
		"store", "dao", "entity", "record", "migration",
	}
)

// Config / settings domain signals.
var (
	configPathSignals  = []string{"config", "configuration", "setting", "env", "builder", "configurer", "customizer", "bean", "parser"}
	configNamePrefixes = []string{"config", "configure", "setting", "option", "env", "apply", "httpsecurity", "websecurity", "springsecurityfilterchain"}
	configNameSuffixes = []string{"config", "settings", "options", "opts", "configuration", "builder", "builders", "configurer", "configurers", "customizer", "customizers", "parser", "filterchain"}
)

// Security / auth / authorization domain signals.
var (
	securityPathSignals = []string{
		"auth", "authentication", "authorization", "security",
		"context", "credential", "token", "access", "intercept",
		"filter", "provider", "repository", "firewall",
	}
	securityNamePrefixes = []string{
		"auth", "authenticate", "authorization", "authorize",
		"login", "logout", "securitycontext", "access", "token", "credential",
	}
	securityNameSuffixes = []string{
		"filter", "manager", "provider", "repository", "handler",
		"interceptor", "evaluator", "context", "firewall",
	}
	authFlowNamePrefixes = []string{
		"usernamepassword", "securitycontext", "savedrequest",
	}
	authFlowNameSuffixes   = []string{"filter", "manager", "provider", "repository", "handler"}
	authFlowPathSignals    = []string{"authentication", "context", "session", "provider", "filter"}
	authFlowProcessSignals = []string{"filter", "manager", "provider", "repository", "handler", "session"}
)

// contextBoost returns a multiplicative score factor (>=1.0) when the
// symbol's name or file path signals relevance to the query's domain.
func contextBoost(queryText string, sm service.SymbolMatch) float64 {
	ql := strings.ToLower(queryText)
	nameL := strings.ToLower(sm.Name)
	pathL := strings.ToLower(sm.FilePath)
	sigL := strings.ToLower(sm.Signature)
	boost := tokenOverlapBoost(queryText, sm)

	if containsAny(ql, httpTriggers...) {
		if containsAny(pathL, httpPathSignals...) {
			boost *= 1.5
		}
		if containsAny(sigL, httpPathSignals...) {
			boost *= 1.3
		}
		if hasPrefixAny(nameL, httpNamePrefixes...) || hasSuffixAny(nameL, httpNameSuffixes...) {
			boost *= 1.5
		}
	}

	if containsAny(ql, dbTriggers...) {
		if containsAny(pathL, dbPathSignals...) {
			boost *= 1.5
		}
		if containsAny(sigL, dbPathSignals...) {
			boost *= 1.3
		}
		if hasPrefixAny(nameL, dbNamePrefixes...) || hasSuffixAny(nameL, dbNameSuffixes...) {
			boost *= 1.5
		}
	}

	if containsAny(ql, configTriggers...) {
		if containsAny(pathL, configPathSignals...) {
			boost *= 1.5
		}
		if containsAny(sigL, configPathSignals...) {
			boost *= 1.3
		}
		if hasPrefixAny(nameL, configNamePrefixes...) || hasSuffixAny(nameL, configNameSuffixes...) {
			boost *= 1.5
		}
	}

	if containsAny(ql, securityTriggers...) {
		if containsAny(pathL, securityPathSignals...) {
			boost *= 1.5
		}
		if containsAny(sigL, securityPathSignals...) {
			boost *= 1.3
		}
		if hasPrefixAny(nameL, securityNamePrefixes...) || hasSuffixAny(nameL, securityNameSuffixes...) {
			boost *= 1.5
		}
	}

	if isAuthFlowQuery(ql) {
		if containsAny(pathL, authFlowPathSignals...) {
			boost *= 1.3
		}
		if containsAny(sigL, authFlowPathSignals...) {
			boost *= 1.3
		}
		if hasPrefixAny(nameL, authFlowNamePrefixes...) || hasSuffixAny(nameL, authFlowNameSuffixes...) {
			boost *= 1.6
		}
	}

	return boost
}

func tokenOverlapBoost(queryText string, sm service.SymbolMatch) float64 {
	return textOverlapBoost(queryText, sm.Name+" "+sm.FilePath+" "+sm.Signature)
}

func processBoost(queryText, processName, heuristicLabel, entryPoint string) float64 {
	overlap := textOverlapCount(queryText, processName+" "+heuristicLabel+" "+entryPoint)
	if overlap == 0 {
		return 1.0
	}
	if overlap > 5 {
		overlap = 5
	}
	boost := 1.0 + 0.25*float64(overlap*overlap)
	if isAuthFlowQuery(strings.ToLower(queryText)) {
		candidate := strings.ToLower(processName + " " + entryPoint)
		if containsAny(candidate, authFlowProcessSignals...) {
			boost *= 1.3
		}
	}
	return boost
}

func textOverlapBoost(queryText, candidateText string) float64 {
	overlap := textOverlapCount(queryText, candidateText)
	if overlap == 0 {
		return 1.0
	}
	if overlap > 4 {
		overlap = 4
	}
	return 1.0 + 0.15*float64(overlap)
}

func textOverlapCount(queryText, candidateText string) int {
	queryTokens := strings.Fields(search.CleanQuery(queryText))
	if len(queryTokens) == 0 {
		return 0
	}

	candidateTokens := strings.Fields(search.CleanQuery(candidateText))
	if len(candidateTokens) == 0 {
		return 0
	}

	tokenSet := make(map[string]bool, len(candidateTokens))
	for _, tok := range candidateTokens {
		tokenSet[canonicalOverlapToken(tok)] = true
	}

	overlap := 0
	seen := make(map[string]bool, len(queryTokens))
	for _, tok := range queryTokens {
		if seen[tok] {
			continue
		}
		seen[tok] = true
		if tokenSet[canonicalOverlapToken(tok)] {
			overlap++
		}
	}
	return overlap
}

func canonicalOverlapToken(tok string) string {
	switch {
	case strings.HasPrefix(tok, "authenticat"):
		return "authenticat"
	case strings.HasPrefix(tok, "authoriz"):
		return "authoriz"
	case strings.HasPrefix(tok, "configur"):
		return "configur"
	case strings.HasPrefix(tok, "customiz"):
		return "customiz"
	case strings.HasPrefix(tok, "intercept"):
		return "intercept"
	case strings.HasPrefix(tok, "advisor"):
		return "advisor"
	case strings.HasPrefix(tok, "securitycontext"):
		return "securitycontext"
	}
	return tok
}

func isAuthFlowQuery(queryLower string) bool {
	hasAuth := containsAny(queryLower, "authenticate", "authenticated", "authentication", "login")
	hasFlow := containsAny(queryLower, "security context", "context", "session", "persist", "request")
	return hasAuth && hasFlow
}

func isSpringMVCDispatchQuery(queryLower string) bool {
	hasDispatcher := containsAny(queryLower, "dispatcherservlet")
	hasControllerFlow := containsAny(queryLower, "controller method", "http request", "response body", "write the response")
	return hasDispatcher || hasControllerFlow
}

func isContextLifecycleQuery(queryLower string) bool {
	hasContext := containsAny(queryLower, "application context", "container")
	hasLifecycle := containsAny(queryLower, "refresh", "lifecycle", "event", "publish")
	return hasContext && hasLifecycle
}

func expandIntentQuery(queryText string) string {
	ql := strings.ToLower(queryText)
	switch {
	case isAuthFlowQuery(ql):
		return queryText + " authentication filter authentication processing filter provider manager security context holder filter repository session success handler failure handler event publisher username password"
	case isSpringMVCDispatchQuery(ql):
		return queryText + " dispatcher servlet DispatcherServlet HandlerExecutionChain handler execution chain HandlerMapping handler mapping HandlerAdapter handler adapter RequestMappingHandlerMapping RequestMappingHandlerAdapter InvocableHandlerMethod RequestResponseBodyMethodProcessor request mapping invocable handler method request response body request response body method processor"
	case isContextLifecycleQuery(ql):
		return queryText + " AbstractApplicationContext ApplicationEventPublisher SimpleApplicationEventMulticaster ContextRefreshedEvent DefaultLifecycleProcessor AnnotationConfigApplicationContext application event publisher context refreshed event application context simple application event multicaster default lifecycle processor annotation config application context"
	default:
		return queryText
	}
}

func labelBoost(queryText string, sm service.SymbolMatch) float64 {
	ql := strings.ToLower(queryText)
	switch {
	case isAuthFlowQuery(ql):
		switch sm.Label {
		case string(graph.LabelClass), string(graph.LabelInterface):
			return 1.25
		case string(graph.LabelConstructor):
			return 1.1
		case string(graph.LabelMethod), string(graph.LabelFunction):
			return 0.95
		case string(graph.LabelFile), string(graph.LabelProperty):
			return 0.85
		default:
			return 1.0
		}
	case isSpringMVCDispatchQuery(ql), isContextLifecycleQuery(ql):
		switch sm.Label {
		case string(graph.LabelClass), string(graph.LabelInterface):
			return 1.2
		case string(graph.LabelConstructor):
			return 1.1
		case string(graph.LabelMethod), string(graph.LabelFunction):
			return 0.93
		case string(graph.LabelFile), string(graph.LabelProperty):
			return 0.85
		default:
			return 1.0
		}
	default:
		return 1.0
	}
}

// containsAny reports whether s contains any of the given substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// hasPrefixAny reports whether s starts with any of the given prefixes.
func hasPrefixAny(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// hasSuffixAny reports whether s ends with any of the given suffixes.
func hasSuffixAny(s string, suffixes ...string) bool {
	for _, sfx := range suffixes {
		if strings.HasSuffix(s, sfx) {
			return true
		}
	}
	return false
}

// centralityBoost returns a mild multiplicative factor (>=1.0) based on
// CALLS/SPAWNS/DELEGATES_TO edge degree. Formula: 1.0 + 0.15*log2(degree+1), capped at 2.0.
func centralityBoost(node *lpg.Node) float64 {
	degree := len(graph.GetIncomingEdges(node, graph.RelCalls)) +
		len(graph.GetOutgoingEdges(node, graph.RelCalls)) +
		len(graph.GetIncomingEdges(node, graph.RelSpawns)) +
		len(graph.GetOutgoingEdges(node, graph.RelSpawns)) +
		len(graph.GetIncomingEdges(node, graph.RelDelegatesTo)) +
		len(graph.GetOutgoingEdges(node, graph.RelDelegatesTo))
	if degree == 0 {
		return 1.0
	}
	boost := 1.0 + 0.15*math.Log2(float64(degree+1))
	if boost > 2.0 {
		return 2.0
	}
	return boost
}
