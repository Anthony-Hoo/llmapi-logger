//go:build race

package integration_test

// raceBuild is true in a build with the race detector, which runs this
// package several times slower. Tests that iterate over a large workload for
// breadth run a representative part of it there and say what they leave out
// (grep raceBuild): the archive read equivalence catalogue and the parse
// timing rounds of TestUnifiedParseDoesNotReadBackOnPostgreSQL.
const raceBuild = true
