//go:build race

package postgres

// raceBuild is true in a build with the race detector, which runs this
// package's code several times slower. Tests that iterate over a large
// generated workload for breadth run a representative part of it there;
// each says what it leaves out (grep raceBuild).
const raceBuild = true
