package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wwwqqwq/frost-aggregator/policy"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: aggregator setup-outer|prove|verify")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "setup-outer":
		err = cmdSetupOuter(os.Args[2:])
	case "prove":
		err = cmdProve(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: aggregator setup-outer|prove|verify")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func cmdSetupOuter(args []string) error {
	fs := flag.NewFlagSet("setup-outer", flag.ContinueOnError)
	sp1Dir := fs.String("sp1-dir", "", "SP1 inner dump directory")
	risc0Dir := fs.String("risc0-dir", "", "RISC0 inner dump directory")
	outerSetup := fs.String("outer-setup", "outer/setup", "outer circuit setup directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sp1Dir == "" || *risc0Dir == "" {
		return fmt.Errorf("--sp1-dir and --risc0-dir required")
	}
	fmt.Println("compiling outer circuit + setup (~4 min)...")
	if err := policy.SetupOuterFromDirs(*sp1Dir, *risc0Dir, *outerSetup); err != nil {
		return err
	}
	fmt.Printf("wrote %s/{outer_ccs.bin,outer_pk.bin,outer_vk.bin}\n", *outerSetup)
	return nil
}

func cmdProve(args []string) error {
	fs := flag.NewFlagSet("prove", flag.ContinueOnError)
	sp1Dir := fs.String("sp1-dir", "", "SP1 inner dump directory")
	risc0Dir := fs.String("risc0-dir", "", "RISC0 inner dump directory")
	outerSetup := fs.String("outer-setup", "outer/setup", "outer circuit setup directory")
	outerProof := fs.String("outer-proof", "outer/proof", "outer proof output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sp1Dir == "" || *risc0Dir == "" {
		return fmt.Errorf("--sp1-dir and --risc0-dir required")
	}
	fmt.Println("proving outer (SP1 + RISC0, 2-of-3)...")
	if err := policy.ProveFromDirs(*sp1Dir, *risc0Dir, *outerSetup, *outerProof); err != nil {
		return err
	}
	fmt.Printf("wrote %s/{outer_proof.bin,outer_vk.bin,frost_outputs.bin,claim_digest.bin}\n", *outerProof)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	outerProof := fs.String("outer-proof", "", "outer proof directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outerProof == "" {
		return fmt.Errorf("--outer-proof required")
	}
	fmt.Println("verifying outer groth16 proof...")
	if err := policy.VerifyOuter(*outerProof); err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}
