package schnorr

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestZKPOverMultipleCurves(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
		// TODO: the code fails on the following curves. Investigate if this is expected.
		// curves.PALLAS(),
		// curves.BLS12377G1(),
		// curves.BLS12377G2(),
		// curves.BLS12381G1(),
		// curves.BLS12381G2(),
		// curves.ED25519(),
	}
	for i, curve := range curveInstances {
		uniqueSessionId := sha3.New256().Sum([]byte("random seed"))
		prover := NewProver(curve, nil, uniqueSessionId)

		secret := curve.Scalar.Random(rand.Reader)
		proof, err := prover.Prove(secret)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		err = Verify(proof, curve, nil, uniqueSessionId)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}

func TestProofVerificationWithAlteredProof(t *testing.T) {
    // Setup the cryptographic parameters.
    curve := curves.K256() // Assuming K256 is one of the supported curves.
    basePoint := curve.NewGeneratorPoint()
    sessionID := []byte("test session ID")

    // Initialize a Prover.
    prover := NewProver(curve, basePoint, sessionID)
    
    // Generate a random secret scalar.
    secret := curve.Scalar.Random(rand.Reader)
    
    // Generate a valid proof using the secret.
    proof, err := prover.Prove(secret)
    require.NoError(t, err, "Proof generation should not encounter an error")

    // Tamper with the proof: Modify the C component.
    alteredC := curve.Scalar.Random(rand.Reader) // Ensure it's likely different.
    proof.C = alteredC

    // Attempt to verify the tampered proof.
    err = Verify(proof, curve, basePoint, sessionID)
    
    // Verification should fail.
    require.Error(t, err, "Verification should fail for an altered proof")
}

func TestProofCommitmentAndDecommitment(t *testing.T) {
    // Setup the cryptographic parameters.
    curve := curves.K256() // Assuming K256 is one of the supported curves.
    basePoint := curve.NewGeneratorPoint()
    sessionID := []byte("test session ID")

    // Initialize a Prover.
    prover := NewProver(curve, basePoint, sessionID)
    
    // Generate a random secret scalar.
    secret := curve.Scalar.Random(rand.Reader)
    
    // Generate a proof and a commitment.
    proof, commitment, err := prover.ProveCommit(secret)
    require.NoError(t, err, "Proof and commitment generation should not encounter an error")

    // Decommit the proof and verify it.
    err = DecommitVerify(proof, commitment, curve, basePoint, sessionID)
    
    // Verification should succeed.
    require.NoError(t, err, "Decommitment and verification should succeed without error")
}

