package policy

import (
	"fmt"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

func SetupOuterFromDirs(sp1Dir, risc0Dir, setupDir string) error {
	loaded, err := loadForPolicy(map[BackendID]string{BackendSP1: sp1Dir, BackendRISC0: risc0Dir}, DefaultPolicy)
	if err != nil {
		return err
	}
	circuit, err := buildFrostCircuit(DefaultPolicy, loaded, false)
	if err != nil {
		return err
	}
	outerCCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	r1csCCS := outerCCS.(*cs.R1CS)
	pk, vk, err := groth16.Setup(r1csCCS)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	return saveOuterArtifacts(setupDir, r1csCCS, pk, vk)
}

func ProveFromDirs(sp1Dir, risc0Dir, setupDir, outDir string) error {
	loaded, err := loadForPolicy(map[BackendID]string{BackendSP1: sp1Dir, BackendRISC0: risc0Dir}, DefaultPolicy)
	if err != nil {
		return err
	}
	art, err := loadOuterArtifacts(setupDir)
	if err != nil {
		return fmt.Errorf("outer setup missing in %s: %w", setupDir, err)
	}
	assign, err := buildFrostCircuit(DefaultPolicy, loaded, true)
	if err != nil {
		return err
	}
	field := ecc.BN254.ScalarField()
	w, err := frontend.NewWitness(assign, field)
	if err != nil {
		return fmt.Errorf("witness: %w", err)
	}
	proof, err := groth16.Prove(art.CCS, art.PK, w, stdgroth16.GetNativeProverOptions(field, field))
	if err != nil {
		return err
	}
	return saveOuter(outDir, proof, art.VK, loaded[BackendSP1].Proof.publicValues, loaded[BackendRISC0].claim)
}

func VerifyOuter(outDir string) error {
	proof := groth16.NewProof(ecc.BN254)
	if err := readFile(filepath.Join(outDir, outerProofFile), proof.ReadFrom); err != nil {
		return err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readFile(filepath.Join(outDir, outerVKFile), vk.ReadFrom); err != nil {
		return err
	}
	frost, err := readFixedLen(filepath.Join(outDir, fileFrostOut), ProofOutputsLen)
	if err != nil {
		return err
	}
	claim, err := readDigest32(filepath.Join(outDir, fileClaimDigest))
	if err != nil {
		return err
	}
	c0, c1 := splitDigest(claim)
	field := ecc.BN254.ScalarField()
	pub, err := frontend.NewWitness(&frostCircuit{
		FrostOutputs: frostVars(frost),
		Claim:        [2]emulated.Element[scalarField]{emulated.ValueOf[scalarField](c0), emulated.ValueOf[scalarField](c1)},
	}, field, frontend.PublicOnly())
	if err != nil {
		return err
	}
	pub, err = pub.Public()
	if err != nil {
		return err
	}
	return groth16.Verify(proof, vk, pub, stdgroth16.GetNativeVerifierOptions(field, field))
}
