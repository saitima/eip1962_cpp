package eip

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

func BenchmarkRandField(t *testing.B) {
	modulus := bytes_(64, "0x6cc11f22d96f2bb1c871e804ef037e69f14a73a84fef3eb014815fd417ad900ce75a70940451e364f0198799e4670dbe217800f488f4d21bd92feb81d3aec457")
	// f := randField(8)
	f := newField(modulus)
	e := f.newFieldElement()
	for i := 0; i < t.N; i++ {
		f.mul(e, f.one, f.one)
	}
}

func BenchmarkBLSPairingWitHex4(t *testing.B) {
	in, err := hex.DecodeString("07301a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000042073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000011a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010108d201000000010000010417f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")
	if err != nil {
		t.Fatal(err)
	}

	t.ResetTimer()
	api := new(API)

	for i := 0; i < t.N; i++ {
		api.Run(in)
	}
}

func BenchmarkBLSPairingWitHex1(t *testing.B) {
	in, err := hex.DecodeString("07301a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000042073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000011a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010108d201000000010000010117f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")
	if err != nil {
		t.Fatal(err)
	}

	t.ResetTimer()
	api := new(API)

	for i := 0; i < t.N; i++ {
		api.Run(in)
	}
}
func BenchmarkBLSPairingWitHex0(t *testing.B) {
	in, err := hex.DecodeString("07301a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000042073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000011a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010108d2010000000100000100")
	if err != nil {
		t.Fatal(err)
	}

	t.ResetTimer()
	api := new(API)

	for i := 0; i < t.N; i++ {
		api.Run(in)
	}
}
func TestBLSPairingWitHex4(t *testing.T) {
	in, err := hex.DecodeString("07301a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000042073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000011a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010108d201000000010000010417f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b828010606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")
	if err != nil {
		t.Fatal(err)
	}
	_, err = new(API).Run(in)
	if err != nil {
		t.Fatal(err)
	}
}
func TestBLSPairingWitHex1(t *testing.T) {
	in, err := hex.DecodeString("07301a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000042073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000011a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010108d2010000000100000100")
	if err != nil {
		t.Fatal(err)
	}
	_, err = new(API).Run(in)
	if err == nil {
		t.Fatal(err)
	}
}

func BenchmarkG2SubGroupCheck(t *testing.B) {
	// base field
	modulus, ok := new(big.Int).SetString("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787", 10)
	if !ok {
		panic("invalid modulus") // @TODO
	}
	q, ok := new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	if !ok {
		panic("invalid g1 order")
	}
	f := newField(modulus.Bytes())
	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, f.one)
	fq2.calculateFrobeniusCoeffs()

	g, err := newG22(fq2, nil, nil, q.Bytes())
	if err != nil {
		panic(err)
	}
	oneBytes := bytes_(48,
		"0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
		"0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
		"0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
		"0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
	)
	one, err := g.fromBytes(oneBytes)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.newFieldElementFromBytes(bytes_(48, "0x04"))
	if err != nil {
		t.Fatal(err)
	}
	a2, b2 := fq2.zero(), fq2.newElement()
	f.copy(b2[0], b)
	f.copy(b2[1], b)
	fq2.copy(g.a, a2)
	fq2.copy(g.b, b2)
	e := g.newPoint()
	for i := 0; i < t.N; i++ {
		g.mulScalar(e, one, g.q)
	}
}

func BenchmarkFq2Frobenius(t *testing.B) {
	modulusBytes := bytes_(48, "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
	f := newField(modulusBytes)
	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, f.one)
	for i := 0; i < t.N; i++ {
		fq2.calculateFrobeniusCoeffs()
	}
}

func BenchmarkFq6Frobenius(t *testing.B) {
	modulusBytes := bytes_(48, "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
	f := newField(modulusBytes)
	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, f.one)
	fq2.calculateFrobeniusCoeffs()

	fq6, err := newFq6(fq2, nil)
	if err != nil {
		panic(err)
	}
	f.copy(fq6.nonResidue[0], f.one)
	f.copy(fq6.nonResidue[1], f.one)
	for i := 0; i < t.N; i++ {
		fq6.calculateFrobeniusCoeffs()
	}
	actual, zero := fq6.zero(), fq6.zero()
	for i := 0; i < t.N; i++ {
		fq6.exp(actual, zero, bigOne)
	}
}
func BenchmarkFq6FrobeniusWithPrecomputation(t *testing.B) {
	modulusBytes := bytes_(48, "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
	f := newField(modulusBytes)
	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, f.one)
	fq2.calculateFrobeniusCoeffs()

	fq6, err := newFq6(fq2, nil)
	if err != nil {
		panic(err)
	}
	f.copy(fq6.nonResidue[0], f.one)
	f.copy(fq6.nonResidue[1], f.one)
	f1, f2, err := constructBaseForFq6AndFq12(fq2, fq6.nonResidue)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < t.N; i++ {
		fq6.calculateFrobeniusCoeffsWithPrecomputation(f1, f2)
	}
}

func BenchmarkFq12Frobenius(t *testing.B) {
	modulusBytes := bytes_(48, "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
	f := newField(modulusBytes)
	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, f.one)
	fq2.calculateFrobeniusCoeffs()

	fq6, err := newFq6(fq2, nil)
	if err != nil {
		panic(err)
	}
	f.copy(fq6.nonResidue[0], f.one)
	f.copy(fq6.nonResidue[1], f.one)
	fq6.calculateFrobeniusCoeffs()

	fq12, err := newFq12(fq6, nil)
	if err != nil {
		panic(err)
	}
	// f.neg(fq12.nonResidue, f.one)
	for i := 0; i < t.N; i++ {
		fq12.calculateFrobeniusCoeffs()
	}
}
func BenchmarkFq12FrobeniusWithPrecomputation(t *testing.B) {
	modulusBytes := bytes_(48, "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
	f := newField(modulusBytes)
	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, f.one)
	fq2.calculateFrobeniusCoeffs()

	fq6, err := newFq6(fq2, nil)
	if err != nil {
		panic(err)
	}
	f.copy(fq6.nonResidue[0], f.one)
	f.copy(fq6.nonResidue[1], f.one)
	fq6.calculateFrobeniusCoeffs()

	fq12, err := newFq12(fq6, nil)
	if err != nil {
		panic(err)
	}
	f1, f2, err := constructBaseForFq6AndFq12(fq2, fq6.nonResidue)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < t.N; i++ {
		fq12.calculateFrobeniusCoeffsWithPrecomputation(f1, f2)
	}
}

func TestFq6Frob(t *testing.T) {
	modulusBytes := bytes_(48, "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
	f := newField(modulusBytes)

	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, f.one)
	fq2.calculateFrobeniusCoeffs()

	fq6, err := newFq6(fq2, nil)
	if err != nil {
		panic(err)
	}
	f.copy(fq6.nonResidue[0], f.one)
	f.copy(fq6.nonResidue[1], f.one)
	fq6.calculateFrobeniusCoeffs()

	fq62, err := newFq6(fq2, nil)
	if err != nil {
		panic(err)
	}
	f.copy(fq62.nonResidue[0], f.one)
	f.copy(fq62.nonResidue[1], f.one)

	f1, f2, err := constructBaseForFq6AndFq12(fq2, fq6.nonResidue)
	if err != nil {
		t.Fatal(err)
	}
	fq62.calculateFrobeniusCoeffsWithPrecomputation(f1, f2)

	for i := 0; i < 6; i++ {
		if !fq2.equal(fq6.frobeniusCoeffs[0][i], fq62.frobeniusCoeffs[0][i]) {
			t.Fatalf("not equal 0 %d\n", i)
		}
		if !fq2.equal(fq6.frobeniusCoeffs[1][i], fq62.frobeniusCoeffs[1][i]) {
			t.Fatalf("not equal 1 %d\n", i)
		}
	}
}

func TestFq12Frob(t *testing.T) {
	modulusBytes := bytes_(48, "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
	f := newField(modulusBytes)

	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, f.one)
	fq2.calculateFrobeniusCoeffs()

	fq6, err := newFq6(fq2, nil)
	if err != nil {
		panic(err)
	}
	f.copy(fq6.nonResidue[0], f.one)
	f.copy(fq6.nonResidue[1], f.one)
	fq6.calculateFrobeniusCoeffs()

	fq12, err := newFq12(fq6, nil)
	if err != nil {
		panic(err)
	}
	fq12.calculateFrobeniusCoeffs()

	_fq12, err := newFq12(fq6, nil)
	if err != nil {
		panic(err)
	}

	f1, f2, err := constructBaseForFq6AndFq12(fq2, fq6.nonResidue)
	if err != nil {
		t.Fatal(err)
	}
	_fq12.calculateFrobeniusCoeffsWithPrecomputation(f1, f2)

	for i := 0; i < 12; i++ {
		if !fq2.equal(fq12.frobeniusCoeffs[i], _fq12.frobeniusCoeffs[i]) {
			t.Fatalf("not equal %d\n", i)
		}
	}
}

func TestFq3Frob(t *testing.T) {
	modulusBytes := bytes_(40, "0x3bcf7bcd473a266249da7b0548ecaeec9635cf44194fb494c07925d6ad3bb4334a400000001")
	f := newField(modulusBytes)
	fq3, err := newFq3(f, nil)
	if err != nil {
		panic(err)
	}
	nonResidue, err := f.newFieldElementFromBytes(bytes_(40, "0x05"))
	if err != nil {
		panic(err)
	}
	f.neg(fq3.nonResidue, nonResidue)
	fq3.calculateFrobeniusCoeffs()

	_fq3, err := newFq3(f, nil)
	if err != nil {
		panic(err)
	}

	f.neg(_fq3.nonResidue, nonResidue)
	f1, err := constructBaseForFq3AndFq6(f, nonResidue)
	if err != nil {
		t.Fatal(err)
	}
	_fq3.calculateFrobeniusCoeffsWithPrecomputation(f1)

	for i := 0; i < 2; i++ {
		for j := 0; j < 3; j++ {
			if !f.equal(fq3.frobeniusCoeffs[i][j], _fq3.frobeniusCoeffs[i][j]) {
				t.Fatalf("not equal %d %d\n", i, j)
			}
		}
	}
}

func BenchmarkBNPairing(t *testing.B) {
	file := "test_vectors/custom/256.json"
	v, err := newTestVectorJSONFromFile(file)
	if err != nil {
		t.Fatal(err)
	}
	in, _, err := v.makeBNPairingBinary()
	if err != nil {
		t.Fatal(err)
	}
	api := new(API)
	for i := 0; i < t.N; i++ {
		api.Run(in)
	}
}

func TestFq6QuadraticFrob(t *testing.T) {
	modulusBytes := bytes_(40, "0x3bcf7bcd473a266249da7b0548ecaeec9635cf44194fb494c07925d6ad3bb4334a400000001")
	f := newField(modulusBytes)
	fq3, err := newFq3(f, nil)
	if err != nil {
		panic(err)
	}
	nonResidue, err := f.newFieldElementFromBytes(bytes_(40, "0x05"))
	if err != nil {
		panic(err)
	}
	f.neg(fq3.nonResidue, nonResidue)
	fq3.calculateFrobeniusCoeffs()

	fq6, err := newFq6Quadratic(fq3, nil)
	if err != nil {
		panic(err)
	}
	fq6.nonResidue = fq3.zero()
	fq6.f.f.copy(fq6.nonResidue[0], fq3.nonResidue)
	fq6.calculateFrobeniusCoeffs()

	_fq6, err := newFq6Quadratic(fq3, nil)
	if err != nil {
		panic(err)
	}
	_fq6.nonResidue = fq3.zero()
	_fq6.f.f.copy(_fq6.nonResidue[0], fq3.nonResidue)
	f1, err := constructBaseForFq3AndFq6(f, nonResidue)
	if err != nil {
		t.Fatal(err)
	}
	_fq6.calculateFrobeniusCoeffsWithPrecomputation(f1)

	for i := 0; i < 6; i++ {
		if !f.equal(fq6.frobeniusCoeffs[i], _fq6.frobeniusCoeffs[i]) {
			t.Fatalf("not equal %d\n", i)
		}
	}
}

func TestFq2Frob(t *testing.T) {
	byteLen := 40
	modulusBytes := bytes_(byteLen, "0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a71660001")
	f := newField(modulusBytes)

	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	nonResidue, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x11")) // decimal: 17
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, nonResidue)
	fq2.calculateFrobeniusCoeffs()

	f1 := constructBaseForFq2AndFq4(f, nonResidue)
	_fq2, err := newFq2(f, nil)
	f.neg(_fq2.nonResidue, nonResidue)
	_fq2.calculateFrobeniusCoeffsWithPrecomputation(f1)
	for i := 0; i < 2; i++ {
		if !f.equal(fq2.frobeniusCoeffs[i], _fq2.frobeniusCoeffs[i]) {
			t.Fatalf("not equal %d\n", i)
		}
	}
}

func TestFq4Frob(t *testing.T) {
	byteLen := 40
	modulusBytes := bytes_(byteLen, "0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a71660001")
	f := newField(modulusBytes)

	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	nonResidue, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x11")) // decimal: 17
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, nonResidue)
	fq2.calculateFrobeniusCoeffs()

	fq4, err := newFq4(fq2, nil)
	if err != nil {
		panic(err)
	}
	fq4.nonResidue = fq2.zero()
	fq4.f.f.copy(fq4.nonResidue[0], fq2.nonResidue)
	fq4.calculateFrobeniusCoeffs()

	f1 := constructBaseForFq2AndFq4(f, nonResidue)

	_fq4, err := newFq4(fq2, nil)
	if err != nil {
		panic(err)
	}
	_fq4.nonResidue = fq2.zero()
	_fq4.f.f.copy(fq4.nonResidue[0], fq2.nonResidue)
	_fq4.calculateFrobeniusCoeffsWithPrecomputation(f1)

}
func TestAteCyclotomicSquaring(t *testing.T) {
	byteLen := 48
	modulusBytes := bytes_(byteLen, "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
	groupBytes := bytes_(byteLen, "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	f := newField(modulusBytes)

	// G1
	a, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x00"))
	if err != nil {
		t.Fatal(err)
	}

	b, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x04"))
	if err != nil {
		t.Fatal(err)
	}

	g1, err := newG1(f, nil, nil, groupBytes)
	if err != nil {
		panic(err)
	}
	f.copy(g1.a, a)
	f.copy(g1.b, b)

	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, f.one)
	fq2.calculateFrobeniusCoeffs()

	// G2
	g2, err := newG22(fq2, nil, nil, groupBytes)
	if err != nil {
		panic(err)
	}
	a2, b2 := fq2.zero(), fq2.newElement()
	f.copy(b2[0], b)
	f.copy(b2[1], b)
	fq2.copy(g2.a, a2)
	fq2.copy(g2.b, b2)

	fq6, err := newFq6(fq2, nil)
	if err != nil {
		panic(err)
	}
	f.copy(fq6.nonResidue[0], f.one)
	f.copy(fq6.nonResidue[1], f.one)
	fq6.calculateFrobeniusCoeffs()

	fq12, err := newFq12(fq6, nil)
	if err != nil {
		panic(err)
	}
	fq12.calculateFrobeniusCoeffs()

	z, ok := new(big.Int).SetString("d201000000010000", 16)
	if !ok {
		panic("invalid exponent")
	}

	bls := newBLSInstance(z, true, 1, g1, g2, fq12, true)

	generatorBytes := bytes_(byteLen,
		"0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
		"0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
	)
	g1One, err := bls.g1.fromBytes(generatorBytes)
	if err != nil {
		panic(err)
	}
	if !bls.g1.isOnCurve(g1One) {
		panic("p is not on curve\n")
	}
	generatorBytes = bytes_(byteLen,
		"0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
		"0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
		"0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
		"0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
	)
	g2One, err := bls.g2.fromBytes(generatorBytes)
	if err != nil {
		panic(err)
	}
	if !bls.g2.isOnCurve(g2One) {
		panic("q is not on curve\n")
	}

	t.Run("fp4", func(t *testing.T) {
		a0, err := fq2.fromBytes(bytes_(byteLen,
			"0x0b4270c208f888badfd366fa9ec5d9fa60645dbae146a835ca2ad1dfe98f80711879a5107250204ef3ca9cf7bc2befd4",
			"0x0f5a7590bf5fac3ebda7c1701710ca11ed23d099321b6e4d9c82f9b990b7340eca69b929436a1f0c47c8c4f6656175cd",
		))
		if err != nil {
			t.Fatal(err)
		}
		a1, err := fq2.fromBytes(bytes_(byteLen,
			"0x15a0193c4b926ca439b9b5997c30d90c6802a185acaf9b21db75e0c4f986762881ee1c3449a951b41fe16343215b6ea1",
			"0x122fd9963a025a602a3c1177d73af8b51c4f0184e299f89b2be6d2cab2e1166d6c186e42d682fce23b9100cd8aa83a3a",
		))
		if err != nil {
			t.Fatal(err)
		}

		c0, err := fq2.fromBytes(bytes_(byteLen,
			"0x0b816db5d6234a256a4a50efdb21fa7efaab51442da95f3cb076059359adecfcf752d6573ed2cf51b74d281b880765d1",
			"0x12967ce4fb32ee65eb051988e9d87d3732e0416b0616cc928fabc9171f05b1db77ed3bece5ba235edd8c9ee58f85c3f9",
		))
		if err != nil {
			t.Fatal(err)
		}
		c1, err := fq2.fromBytes(bytes_(byteLen,
			"0x15899c4dbd2095cf1ebca71c04d9550dca2148ffdd09962de4f72bda677d82c63412096fe2747d75e5632395037e705f",
			"0x177bd8e3183e8f127418313fa03dd9d7a5f0120199b8177c34ba8a2dcda69d849754898a8b05ba4d41127c8791d417f2",
		))
		if err != nil {
			t.Fatal(err)
		}
		actual0 := fq2.newElement()
		actual1 := fq2.newElement()
		fq12.fp4Square(actual0, actual1, a0, a1)
		if !fq2.equal(actual0, c0) {
			t.Fatalf("bad fp4 squaring c0")
		}
		if !fq2.equal(actual1, c1) {
			t.Fatalf("bad fp4 squaring c1")
		}
	})

	t.Run("cyclotomic", func(t *testing.T) {
		a, err := fq12.fromBytes(bytes_(byteLen,
			"0x0d7570ed58f9144d1d07aec7f71789abc7bb35ccbcefa565fdb05384c4640d7f3975818880ddecce085c8cdf05b67316",
			"0x13f68ee2f88867e45ae96018c24f0d4bd9e27113289acb89dd3716d900969f6910a23c2dfd41832a1e869b7fcea4b96e",
			"0x14a4c1a6e3964f0afeb8e5cadffd3962768e4025dfa63c1cc41596e27190c9894c0618e7b15c1d107cf178a58eea7c9e",
			"0x0f940c3dff537227834088ab34ef6d316b2dbb80e3db81124e4ce2f8bc6dc2f02c01a4db06c6d329cb27003644b2c3fa",
			"0x11aaa80237c7b110a8f8732d6be387ab319b1ccab8dceca169c6c4027c5c0d3f0af1d16dc81dde1ba062eab9fd466310",
			"0x02ce8b36d8dbc9bff9acc927d180cbe0546aae93968fe4d52eb0b6f91d1460b8473ebbfd17aa10efa277c512fca8bdb4",
			"0x0799eef1bc166b5b1335c384d630e8aec3b1ad4c768aa434ec76639c5ad72bad2f08926ef7807d23db194e0fff4dc7c8",
			"0x164ca37b093fe7a562716311806c1b2e63cbfa0988e0da46f1de36ea233447be1c193640c3a8a676de9e82ab3d741543",
			"0x15e48e2930ebac2456f115e6084934523e1f13e3fdac7d958a7079c9daeb0c50147d45675e9c983c6d5d18f62e44f804",
			"0x0e010b685be926c70cfe53597da30085ba7b49e19f00877a9abf36876bb479eed610c6e75541e05222d45666283136b2",
			"0x08563ab4c30e4673db6e9edafacc595f11b26c7a649c828357e1e578f68f6d00cbb9d9ceec8a43227126d4a6c309804b",
			"0x0f908463844b78dd03566e50d1d06d8d480bae1c1cc4082f9e0339e0d205d1b9e92fbb32ac2129f6967d707505f89288",
		))
		if err != nil {
			t.Fatal(err)
		}
		actual := fq12.newElement()

		e, err := fq12.fromBytes(bytes_(byteLen,
			"0x08b310084d7264ed52daf785d050b052ffaa4ad751adcac1439f71963958af64ade25509ae9b6e354e1811089d5a0765",
			"0x0cf19c2d02f23e229dcdd2a353a70e05da7cbc8abf472722aed1ab2f3932ed1993daef46570098e63147439c47a8fe1e",
			"0x10149bb5daef93709c0d52e81929164da95b7c0f51555b00e4710f8881233165d383449ae5d17e17bb8bdd7e6d0414ac",
			"0x17d5104ede7218d72b367e103f9d81c1db50c127c25ab1714678bdb08a0dad90da4e51709f041616d7e5b5fe5d090add",
			"0x0c3155370d574b913ad5339fa8d6292042ccab0df2baeb39d59c9c31a2ac0813ed563d4206e5889326c380702030b79a",
			"0x05abb41b3e4a8678fac91b0da34c14cc134621761b14e9bb48b69867f34af57e892f366c7957fe7d7cb4c2c255be6709",
			"0x0af04eed2765cfcbed916ef30948c00db3203029922d02c4bd13eae900df152c0c9aafd4bc89da5d4b04abff4dbe23d5",
			"0x080e44de4918e6f2819a95e347ff88d954ff59040cd144fed2209c8f2d0f6e42a83259c84cd5264e14f7b5d06730c559",
			"0x03e9f4c25d72daba4dd01c3289a82de75e2f4eb149d6e0310f209f08afda1831c4992080a3d5d8b4d9277b9e1a694856",
			"0x125acac5e16a8e33cb3d7e7f5aa2be11ee3caf9432fd445bd50bb1d547a7c18a7bcdfa873f26ef257edb4e625159208a",
			"0x0a9143f7e6e03b24011bdf08e60d204d86a3be400c644b75e96c56651f9c7312a7f7655fd3df6bdf7120e88120241bff",
			"0x05d18688b95212f40298963f2c560c45596df2c4c9a12214106efa2de9b72d5912cfae8f2714528161a17b442fee0797",
		))
		if err != nil {
			t.Fatal(err)
		}
		fq12.cyclotomicSquare(actual, a)
		if !fq12.equal(actual, e) {
			t.Fatalf("invalid squaring")
		}
	})
}

func TestGenerateG23MulPoint(t *testing.T) {
	byteLen := 40
	modulusBytes := bytes_(byteLen, "0x3bcf7bcd473a266249da7b0548ecaeec9635cf44194fb494c07925d6ad3bb4334a400000001")
	groupBytes := bytes_(byteLen, "0x3bcf7bcd473a266249da7b0548ecaeec9635d1330ea41a9e35e51200e12c90cd65a71660001")

	f := newField(modulusBytes)

	fq3, err := newFq3(f, nil)
	if err != nil {
		panic(err)
	}
	fq3.nonResidue, err = f.newFieldElementFromBytes(bytes_(byteLen, "0x05"))
	if err != nil {
		panic(err)
	}
	fq3.calculateFrobeniusCoeffs()

	g, err := newG23(fq3, nil, nil, groupBytes)
	if err != nil {
		panic(err)
	}

	oneBytes := bytes_(byteLen,
		"0x34f7320a12b56ce532bccb3b44902cbaa723cd60035ada7404b743ad2e644ad76257e4c6813",
		"0xcf41620baa52eec50e61a70ab5b45f681952e0109340fec84f1b2890aba9b15cac5a0c80fa",
		"0x11f99170e10e326433cccb8032fb48007ca3c4e105cf31b056ac767e2cb01258391bd4917ce",
		"0x3a65968f03cc64d62ad05c79c415e07ebd38b363ec48309487c0b83e1717a582c1b60fecc91",
		"0xca5e8427e5db1506c1a24cefc2451ab3accaea5db82dcb0c7117cc74402faa5b2c37685c6e",
		"0xf75d2dd88302c9a4ef941307629a1b3e197277d83abb715f647c2e55a27baf782f5c60e7f7",
	)
	one := g.newPoint()
	t.Run("FromBytes & ToBytes", func(t *testing.T) {
		one, err = g.fromBytes(oneBytes)
		if err != nil {
			t.Fatal(err)
		}
		q, err := g.fromBytes(
			g.toBytes(one),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !g.equal(one, q) {
			t.Logf("invalid out ")
		}
	})
	a, err := f.newFieldElementFromBytes(bytes_(byteLen, "0xb"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.newFieldElementFromBytes(bytes_(byteLen, "0xd68c7b1dc5dd042e957b71c44d3d6c24e683fc09b420b1a2d263fde47ddba59463d0c65282"))
	if err != nil {
		t.Fatal(err)
	}

	twist, twist2, twist3 := fq3.newElement(), fq3.newElement(), fq3.newElement()
	f.copy(twist[0], f.zero)
	f.copy(twist[1], f.one)
	fq3.square(twist2, twist)
	fq3.mul(twist3, twist2, twist)
	fq3.mulByFq(g.a, twist2, a)
	fq3.mulByFq(g.b, twist3, b)

	// fmt.Printf("a: %s\n", g.f.toString(g.a))
	// fmt.Printf("b: %s\n", g.f.toString(g.b))

	s, _ := rand.Int(rand.Reader, new(big.Int).SetBytes(bytes_(-1, "0x3a36d8b6f03826ec4786c8f4d0be06f897f7173d0c0")))

	// fmt.Printf("s: %x\n", s)
	e := g.newPoint()
	g.mulScalar(e, one, s)
	g.affine(e, e)
	// fmt.Printf("e: %s\n", g.toString(e))

}

func BenchmarkBLSPairing(t *testing.B) {
	file := "test_vectors/custom/384.json"
	v, err := newTestVectorJSONFromFile(file)
	if err != nil {
		t.Fatal(err)
	}
	in, _, err := v.makeBLSPairingBinary()
	if err != nil {
		t.Fatal(err)
	}

	t.ResetTimer()
	api := new(API)
	for i := 0; i < t.N; i++ {
		api.Run(in)
	}
}

func TestWnaf(t *testing.T) {
	byteLen := 32
	s := new(big.Int).SetBytes(bytes_(byteLen, "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"))
	_ = wnaf(s, 3)
	// t.Logf("s: %x\n", res)
}

func TestG1WnafMul(t *testing.T) {
	// base field
	byteLen := 32
	modulusBytes := bytes_(byteLen, "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47")
	groupBytes := bytes_(byteLen, "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")

	f := newField(modulusBytes)
	a := bytes_(byteLen, "0x00")
	b := bytes_(byteLen, "0x03")
	g, err := newG1(f, a, b, groupBytes)
	if err != nil {
		panic(err)
	}
	oneBytes := bytes_(byteLen,
		"0x01",
		"0x02",
	)
	e1, e2 := g.newPoint(), g.zero()
	one := g.newPoint()
	one, err = g.fromBytes(oneBytes)
	if err != nil {
		t.Fatal(err)
	}

	// scalar, _ := rand.Int(rand.Reader, big.NewInt(10))
	// scalar := big.NewInt(13)
	// scalar := new(big.Int).Sub(g.q, big.NewInt(1))
	g.mulScalar(e1, one, g.q)
	if !g.equal(e1, g.zero()) {
		t.Fatalf("bad scalar mul for e1")
	}
	g.wnafMul(e2, one, g.q)
	if !g.equal(e2, g.zero()) {
		t.Fatalf("bad wnaf mul for e2")
	}
	if !g.equal(e1, e2) {
		t.Logf("e1: %s\n", g.toString(e1))
		t.Logf("e2: %s\n", g.toString(e2))
		t.Fatalf("bad wnaf mul\n")
	}
}
func TestFq2768Bit(t *testing.T) {
	byteLen := 96
	modulusBytes := bytes_(byteLen, "0x0001c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db117e776f218059db80f0da5cb537e38685acce9767254a4638810719ac425f0e39d54522cdd119f5e9063de245e8001")
	f := newField(modulusBytes)
	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	nonResidue, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x0d")) // decimal 13
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, nonResidue)
	fq2.calculateFrobeniusCoeffs()

	zero := fq2.zero()
	one := fq2.one()
	actual := fq2.newElement()
	expected := fq2.newElement()

	_fq2One := bytes_(byteLen,
		"0x01",
		"0x00",
	)
	t.Run("FromBytes & ToBytes", func(t *testing.T) {
		a, err := fq2.fromBytes(_fq2One)
		if err != nil {
			t.Fatal(err)
		}
		if !fq2.equal(a, fq2.one()) {
			t.Fatalf("bad fromBytes")
		}
		b, err := fq2.fromBytes(
			fq2.toBytes(a),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !fq2.equal(a, b) {
			t.Fatalf("not equal")
		}
	})

	t.Run("Addition", func(t *testing.T) {
		fq2.add(actual, zero, zero)
		if !fq2.equal(actual, zero) {
			t.Fatalf("bad add")
		}
		fq2.add(actual, one, zero)
		if !fq2.equal(actual, one) {
			t.Fatalf("bad add")
		}
		fq2.add(actual, zero, zero)
		if !fq2.equal(actual, zero) {
			t.Fatalf("bad add")
		}
	})
	t.Run("Substraction", func(t *testing.T) {
		fq2.sub(actual, zero, zero)
		if !fq2.equal(actual, zero) {
			t.Fatalf("bad substraction 1")
		}
		fq2.sub(actual, one, zero)
		if !fq2.equal(actual, one) {
			t.Fatalf("bad substraction 2")
		}
		fq2.sub(actual, one, one)
		if !fq2.equal(actual, zero) {
			t.Fatalf("bad substraction 3")
		}
	})

	t.Run("Negation", func(t *testing.T) {
		fq2.sub(expected, zero, one)
		fq2.neg(actual, one)
		if !fq2.equal(expected, actual) {
			t.Fatalf("bad negation")
		}
	})
	t.Run("Multiplication", func(t *testing.T) {
		fq2.mul(actual, zero, zero)
		if !fq2.equal(actual, zero) {
			t.Fatalf("bad multiplication 1")
		}
		fq2.mul(actual, one, zero)
		if !fq2.equal(actual, zero) {
			t.Fatalf("bad multiplication 2")
		}
		fq2.mul(actual, zero, one)
		if !fq2.equal(actual, zero) {
			t.Fatalf("bad multiplication 2")
		}
		fq2.mul(actual, one, one)
		if !fq2.equal(actual, one) {
			t.Fatalf("bad multiplication 2")
		}
	})

	t.Run("Squaring", func(t *testing.T) {
		fq2.square(actual, zero)
		if !fq2.equal(actual, zero) {
			t.Fatalf("bad squaring 1")
		}
		fq2.square(actual, one)
		if !fq2.equal(actual, one) {
			t.Fatalf("bad squaring 2")
		}
		fq2.double(expected, one)
		fq2.square(actual, expected)
		fq2.mul(expected, expected, expected)
		if !fq2.equal(expected, actual) {
			t.Fatalf("bad squaring 3")
		}
	})

	t.Run("Inverse", func(t *testing.T) {
		fq2.inverse(actual, zero)
		if !fq2.equal(actual, zero) {
			t.Fatalf("bad inversion 1")
		}
		fq2.inverse(actual, one)
		if !fq2.equal(actual, one) {
			t.Fatalf("bad inversion 2")
		}
		fq2.double(expected, one)
		fq2.inverse(actual, expected)
		fq2.mul(expected, actual, expected)
		if !fq2.equal(expected, one) {
			t.Fatalf("bad inversion 3")
		}
	})

	t.Run("Exponentiation", func(t *testing.T) {
		fq2.exp(actual, zero, bigZero)
		if !fq2.equal(actual, one) {
			t.Fatalf("bad exponentiation 1")
		}
		fq2.exp(actual, zero, bigOne)
		if !fq2.equal(actual, zero) {
			t.Logf("actual %s\n", fq2.toString(actual))
			t.Fatalf("bad exponentiation 2")
		}
		fq2.exp(actual, one, bigZero)
		if !fq2.equal(actual, one) {
			t.Fatalf("bad exponentiation 3")
		}
		fq2.exp(actual, one, bigOne)
		if !fq2.equal(actual, one) {
			t.Fatalf("bad exponentiation 4")
		}
		fq2.double(expected, one)
		fq2.exp(actual, expected, big.NewInt(2))
		fq2.square(expected, expected)
		if !fq2.equal(expected, actual) {
			t.Fatalf("bad exponentiation 4")
		}
	})
}

func TestFq4768(t *testing.T) {
	byteLen := 96
	modulusBytes := bytes_(byteLen, "0x1c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db117e776f218059db80f0da5cb537e38685acce9767254a4638810719ac425f0e39d54522cdd119f5e9063de245e8001")
	f := newField(modulusBytes)

	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	nonResidue, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x0d")) // decimal: 17
	if err != nil {
		panic(err)
	}
	f.neg(fq2.nonResidue, nonResidue)
	fq2.calculateFrobeniusCoeffs()

	fq4, err := newFq4(fq2, nil)
	if err != nil {
		panic(err)
	}
	fq4.nonResidue = fq2.zero()
	fq4.calculateFrobeniusCoeffs()

	zero := fq4.zero()
	one := fq4.one()
	actual := fq4.newElement()
	expected := fq4.newElement()

	_fq4One := bytes_(96,
		"0x01", "0x00",
		"0x00", "0x00",
	)
	t.Run("FromBytes & ToBytes", func(t *testing.T) {
		a, err := fq4.fromBytes(_fq4One)
		if err != nil {
			t.Fatal(err)
		}
		if !fq4.equal(a, fq4.one()) {
			t.Fatalf("bad fromBytes")
		}
		b, err := fq4.fromBytes(
			fq4.toBytes(a),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !fq4.equal(a, b) {
			t.Fatalf("not equal")
		}
	})

	t.Run("Addition", func(t *testing.T) {
		fq4.add(actual, zero, zero)
		if !fq4.equal(actual, zero) {
			t.Fatalf("bad add")
		}
		fq4.add(actual, one, zero)
		if !fq4.equal(actual, one) {
			t.Fatalf("bad add")
		}
		fq4.add(actual, zero, zero)
		if !fq4.equal(actual, zero) {
			t.Fatalf("bad add")
		}
	})
	t.Run("Substraction", func(t *testing.T) {
		fq4.sub(actual, zero, zero)
		if !fq4.equal(actual, zero) {
			t.Fatalf("bad substraction 1")
		}
		fq4.sub(actual, one, zero)
		if !fq4.equal(actual, one) {
			t.Fatalf("bad substraction 2")
		}
		fq4.sub(actual, one, one)
		if !fq4.equal(actual, zero) {
			t.Fatalf("bad substraction 3")
		}
	})

	t.Run("Negation", func(t *testing.T) {
		fq4.sub(expected, zero, one)
		fq4.neg(actual, one)
		if !fq4.equal(expected, actual) {
			t.Fatalf("bad negation")
		}
	})
	t.Run("Multiplication", func(t *testing.T) {
		fq4.mul(actual, zero, zero)
		if !fq4.equal(actual, zero) {
			t.Fatalf("bad multiplication 1")
		}
		fq4.mul(actual, one, zero)
		if !fq4.equal(actual, zero) {
			t.Fatalf("bad multiplication 2")
		}
		fq4.mul(actual, zero, one)
		if !fq4.equal(actual, zero) {
			t.Fatalf("bad multiplication 2")
		}
		fq4.mul(actual, one, one)
		if !fq4.equal(actual, one) {
			t.Fatalf("bad multiplication 2")
		}
	})

	t.Run("Squaring", func(t *testing.T) {
		fq4.square(actual, zero)
		if !fq4.equal(actual, zero) {
			t.Fatalf("bad squaring 1")
		}
		fq4.square(actual, one)
		if !fq4.equal(actual, one) {
			t.Fatalf("bad squaring 2")
		}
		fq4.double(expected, one)
		fq4.square(actual, expected)
		fq4.mul(expected, expected, expected)
		if !fq4.equal(expected, actual) {
			t.Fatalf("bad squaring 3")
		}
	})

	t.Run("Inverse", func(t *testing.T) {
		fq4.inverse(actual, zero)
		if !fq4.equal(actual, zero) {
			t.Fatalf("bad inversion 1")
		}
		fq4.inverse(actual, one)
		if !fq4.equal(actual, one) {
			t.Fatalf("bad inversion 2")
		}
		fq4.double(expected, one)
		fq4.inverse(actual, expected)
		fq4.mul(expected, actual, expected)
		if !fq4.equal(expected, one) {
			t.Fatalf("bad inversion 3")
		}
	})

	t.Run("Exponentiation", func(t *testing.T) {
		fq4.exp(actual, zero, bigZero)
		if !fq4.equal(actual, one) {
			t.Fatalf("bad exponentiation 1")
		}
		fq4.exp(actual, zero, bigOne)
		if !fq4.equal(actual, zero) {
			t.Logf("actual %s\n", fq4.toString(actual))
			t.Fatalf("bad exponentiation 2")
		}
		fq4.exp(actual, one, bigZero)
		if !fq4.equal(actual, one) {
			t.Fatalf("bad exponentiation 3")
		}
		fq4.exp(actual, one, bigOne)
		if !fq4.equal(actual, one) {
			t.Fatalf("bad exponentiation 4")
		}
		fq4.double(expected, one)
		fq4.exp(actual, expected, big.NewInt(2))
		fq4.square(expected, expected)
		if !fq4.equal(expected, actual) {
			t.Fatalf("bad exponentiation 4")
		}
	})
}

func TestG1768(t *testing.T) {
	// base field
	byteLen := 96
	modulusBytes := bytes_(byteLen, "0x1c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db117e776f218059db80f0da5cb537e38685acce9767254a4638810719ac425f0e39d54522cdd119f5e9063de245e8001")
	groupBytes := bytes_(byteLen, "0x1c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db117e776f218059db80f0da5cb537e38685acce9767254a4638810719ac425f0e39d54522cdd119f5e9063de245e8001")

	f := newField(modulusBytes)
	a := bytes_(byteLen, "0x02")
	b := bytes_(byteLen, "0x1373684a8c9dcae7a016ac5d7748d3313cd8e39051c596560835df0c9e50a5b59b882a92c78dc537e51a16703ec9855c77fc3d8bb21c8d68bb8cfb9db4b8c8fba773111c36c8b1b4e8f1ece940ef9eaad265458e06372009c9a0491678ef4")
	g, err := newG1(f, a, b, groupBytes)
	if err != nil {
		panic(err)
	}
	zero := g.zero()
	oneBytes := bytes_(byteLen,
		"0x1013b42397c8b004d06f0e98fbc12e8ee65adefcdba683c5630e6b58fb69610b02eab1d43484ddfab28213098b562d799243fb14330903aa64878cfeb34a45d1285da665f5c3f37eb76b86209dcd081ccaef03e65f33d490de480bfee06db",
		"0xe3eb479d308664381e7942d6c522c0833f674296169420f1dd90680d0ba6686fc27549d52e4292ea5d611cb6b0df32545b07f281032d0a71f8d485e6907766462e17e8dd55a875bd36fe4cd42cac31c0629fb26c333fe091211d0561d10e",
	)
	actual, expected := g.newPoint(), g.zero()
	one := g.newPoint()
	t.Run("FromBytes & ToBytes", func(t *testing.T) {
		one, err = g.fromBytes(oneBytes)
		if err != nil {
			t.Fatal(err)
		}
		q, err := g.fromBytes(
			g.toBytes(one),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !g.equal(one, q) {
			t.Logf("invalid out ")
		}
	})

	t.Run("Is on curve", func(t *testing.T) {
		if !g.isOnCurve(one) {
			t.Fatalf("point is not on the curve")
		}
	})

	t.Run("Copy", func(t *testing.T) {
		q := g.newPoint()
		g.copy(q, one)
		if !g.equal(q, one) {
			t.Fatalf("bad point copy")
		}
	})

	t.Run("Equality", func(t *testing.T) {
		if !g.equal(zero, zero) {
			t.Fatal("bad equality 1")
		}
		if !g.equal(one, one) {
			t.Fatal("bad equality 2")
		}
		if g.equal(one, zero) {
			t.Fatal("bad equality 3")
		}
	})

	t.Run("Affine", func(t *testing.T) {
		g.double(actual, one)
		g.sub(expected, actual, one)
		g.affine(expected, expected)
		if !g.equal(expected, one) {
			t.Fatal("invalid affine ops")
		}
	})

	t.Run("Addition", func(t *testing.T) {
		g.add(actual, zero, zero)
		if !g.equal(actual, zero) {
			t.Fatal("bad addition 1")
		}
		g.add(actual, one, zero)
		if !g.equal(actual, one) {
			t.Fatal("bad addition 2")
		}
		g.add(actual, zero, one)
		if !g.equal(actual, one) {
			t.Fatal("bad addition 3")
		}
	})
	t.Run("Substraction", func(t *testing.T) {
		g.sub(actual, zero, zero)
		if !g.equal(actual, zero) {
			t.Fatal("bad substraction 1")
		}
		g.sub(actual, one, zero)
		if !g.equal(actual, one) {
			t.Fatal("bad substraction 2")
		}
		g.sub(actual, one, one)
		if !g.equal(actual, zero) {
			t.Fatal("bad substraction 3")
		}
	})
	t.Run("Negation", func(t *testing.T) {
		g.neg(actual, zero)
		if !g.equal(actual, zero) {
			t.Fatal("bad negation 1")
		}
		g.neg(actual, one)
		g.sub(expected, zero, one)
		if !g.equal(actual, expected) {
			t.Fatal("bad negation 2")
		}
	})

	t.Run("Doubling", func(t *testing.T) {
		g.double(actual, zero)
		if !g.equal(actual, zero) {
			t.Fatal("bad doubling 1")
		}
		g.add(expected, one, one)
		g.double(actual, one)
		if !g.equal(actual, expected) {
			t.Fatal("bad addition 2")
		}
	})

	t.Run("Scalar Multiplication", func(t *testing.T) {
		g.mulScalar(actual, zero, bigZero)
		if !g.equal(actual, zero) {
			t.Fatal("bad scalar multiplication 1")
		}
		g.mulScalar(actual, zero, bigOne)
		if !g.equal(actual, zero) {
			t.Fatal("bad scalar multiplication 2")
		}
		g.mulScalar(actual, one, bigZero)
		if !g.equal(actual, zero) {
			t.Fatal("bad scalar multiplication 3")
		}
		g.mulScalar(actual, one, bigOne)
		if !g.equal(actual, one) {
			t.Fatal("bad scalar multiplication 4")
		}
	})
	t.Run("Wnaf Multiplication", func(t *testing.T) {
		g.wnafMul(actual, zero, bigZero)
		if !g.equal(actual, zero) {
			t.Fatal("bad scalar multiplication 1")
		}
		g.wnafMul(actual, zero, bigOne)
		if !g.equal(actual, zero) {
			t.Fatal("bad scalar multiplication 2")
		}
		g.wnafMul(actual, one, bigZero)
		if !g.equal(actual, zero) {
			t.Fatal("bad scalar multiplication 3")
		}
		g.wnafMul(actual, one, bigOne)
		if !g.equal(actual, one) {
			t.Fatal("bad scalar multiplication 4")
		}
	})

	t.Run("Multi Exponentiation", func(t *testing.T) {
		count := 1000
		bases := make([]*pointG1, count)
		scalars := make([]*big.Int, count)
		// prepare bases
		// bases: S[0]*G, S[1]*G ... S[n-1]*G
		for i, j := 0, count-1; i < count; i, j = i+1, j-1 {
			// TODO : make sure that s is unique
			scalars[j], _ = rand.Int(rand.Reader, big.NewInt(10000))
			bases[i] = g.zero()
			g.mulScalar(bases[i], one, scalars[j])
		}

		// expected
		//  S[n-1]*P[1], S[n-2]*P[2] ... S[0]*P[n-1]
		expected, tmp := g.zero(), g.zero()
		for i := 0; i < count; i++ {
			g.mulScalar(tmp, bases[i], scalars[i])
			g.add(expected, expected, tmp)
		}
		result := g.zero()
		g.multiExp(result, bases, scalars)
		if !g.equal(expected, result) {
			t.Fatalf("bad multi-exponentiation")
		}
	})
}

func TestG22768(t *testing.T) {
	byteLen := 96
	modulusBytes := bytes_(byteLen, "0x1c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db117e776f218059db80f0da5cb537e38685acce9767254a4638810719ac425f0e39d54522cdd119f5e9063de245e8001")
	groupBytes := bytes_(byteLen, "0x1c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db117e776f218059db80f0da5cb537e38685acce9767254a4638810719ac425f0e39d54522cdd119f5e9063de245e8001")

	f := newField(modulusBytes)
	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}
	nonResidue, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x0d")) // decimal 13
	if err != nil {
		panic(err)
	}
	f.copy(fq2.nonResidue, nonResidue)
	fq2.calculateFrobeniusCoeffs()

	g, err := newG22(fq2, nil, nil, groupBytes)
	if err != nil {
		panic(err)
	}
	zero := g.zero()
	oneBytes := bytes_(byteLen,
		"0xf1b7155ed4e903332835a5de0f327aa11b2d74eb8627e3a7b833be42c11d044b5cf0ae49850eeb07d90c77c67256474b2febf924aca0bfa2e4dacb821c91a04fd0165ac8debb2fc1e763a5c32c2c9f572caa85a91c5243ec4b2981af8904",
		"0xd49c264ec663e731713182a88907b8e979ced82ca592777ad052ec5f4b95dc78dc2010d74f82b9e6d066813ed67f3af1de0d5d425da7a19916cf103f102adf5f95b6b62c24c7d186d60b4a103e157e5667038bb2e828a3374d6439526272",
		"0x4b0e2fef08096ebbaddd2d7f288c4acf17b2267e21dc5ce0f925cd5d02209e34d8b69cc94aef5d90af34d3cd98287ace8f1162079cd2d3d7e6c6c2c073c24a359437e75638a1458f4b2face11f8d2a5200b14d6f9dd0fdd407f04be620ee",
		"0xbc1925e7fcb64f6f8697cd5e45fae22f5688e51b30bd984c0acdc67d2962520e80d31966e3ec477909ecca358be2eee53c75f55a6f7d9660dd6f3d4336ad50e8bfa5375791d73b863d59c422c3ea006b013e7afb186f2eaa9df68f4d6098",
	)
	actual, expected := g.newPoint(), g.zero()
	one := g.newPoint()
	a, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x02"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x1373684a8c9dcae7a016ac5d7748d3313cd8e39051c596560835df0c9e50a5b59b882a92c78dc537e51a16703ec9855c77fc3d8bb21c8d68bb8cfb9db4b8c8fba773111c36c8b1b4e8f1ece940ef9eaad265458e06372009c9a0491678ef4"))
	if err != nil {
		t.Fatal(err)
	}
	twist, twist2, twist3 := fq2.newElement(), fq2.newElement(), fq2.newElement()
	f.copy(twist[0], f.zero)
	f.copy(twist[1], f.one)
	fq2.square(twist2, twist)
	fq2.mul(twist3, twist2, twist)

	a2, b2 := fq2.newElement(), fq2.newElement()
	fq2.mulByFq(a2, twist2, a)
	fq2.mulByFq(b2, twist3, b)
	fq2.copy(g.a, a2)
	fq2.copy(g.b, b2)

	t.Run("FromBytes & ToBytes", func(t *testing.T) {
		one, err = g.fromBytes(oneBytes)
		if err != nil {
			t.Fatal(err)
		}
		q, err := g.fromBytes(
			g.toBytes(one),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !g.equal(one, q) {
			t.Logf("invalid out ")
		}
	})

	t.Run("Is on curve", func(t *testing.T) {
		if !g.isOnCurve(one) {
			t.Fatalf("point is not on the curve")
		}
	})

	t.Run("Copy", func(t *testing.T) {
		q := g.newPoint()
		g.copy(q, one)
		if !g.equal(q, one) {
			t.Fatalf("bad point copy")
		}
	})

	t.Run("Equality", func(t *testing.T) {
		if !g.equal(zero, zero) {
			t.Fatal("bad equality 1")
		}
		if !g.equal(one, one) {
			t.Fatal("bad equality 2")
		}
		if g.equal(one, zero) {
			t.Fatal("bad equality 3")
		}
	})

	t.Run("Affine", func(t *testing.T) {
		g.double(actual, one)
		g.sub(expected, actual, one)
		g.affine(expected, expected)
		if !g.equal(expected, one) {
			t.Fatal("invalid affine ops")
		}
	})

	t.Run("Addition", func(t *testing.T) {
		g.add(actual, zero, zero)
		if !g.equal(actual, zero) {
			t.Fatal("bad addition 1")
		}
		g.add(actual, one, zero)
		if !g.equal(actual, one) {
			t.Fatal("bad addition 2")
		}
		g.add(actual, zero, one)
		if !g.equal(actual, one) {
			t.Fatal("bad addition 3")
		}
	})

	t.Run("Substraction", func(t *testing.T) {
		g.sub(actual, zero, zero)
		if !g.equal(actual, zero) {
			t.Fatal("bad substraction 1")
		}
		g.sub(actual, one, zero)
		if !g.equal(actual, one) {
			t.Fatal("bad substraction 2")
		}
		g.sub(actual, one, one)
		if !g.equal(actual, zero) {
			t.Fatal("bad substraction 3")
		}
	})
	t.Run("Negation", func(t *testing.T) {
		g.neg(actual, zero)
		if !g.equal(actual, zero) {
			t.Fatal("bad negation 1")
		}
		g.neg(actual, one)
		g.sub(expected, zero, one)
		if !g.equal(actual, expected) {
			t.Fatal("bad negation 2")
		}
	})

	t.Run("Doubling", func(t *testing.T) {
		g.double(actual, zero)
		if !g.equal(actual, zero) {
			t.Fatal("bad doubling 1")
		}
		g.add(expected, one, one)
		g.double(actual, one)
		if !g.equal(actual, expected) {
			t.Fatal("bad addition 2")
		}
	})

	t.Run("Scalar Multiplication", func(t *testing.T) {
		g.mulScalar(actual, zero, bigZero)
		if !g.equal(actual, zero) {
			t.Fatal("bad scalar multiplication 1")
		}
		g.mulScalar(actual, zero, bigOne)
		if !g.equal(actual, zero) {
			t.Fatal("bad scalar multiplication 2")
		}
		g.mulScalar(actual, one, bigZero)
		if !g.equal(actual, zero) {
			t.Fatal("bad scalar multiplication 3")
		}
		g.mulScalar(actual, one, bigOne)
		if !g.equal(actual, one) {
			t.Fatal("bad scalar multiplication 4")
		}
	})

	t.Run("Multi Exponentiation", func(t *testing.T) {
		count := 1000
		bases := make([]*pointG22, count)
		scalars := make([]*big.Int, count)
		// prepare bases
		// bases: S[0]*G, S[1]*G ... S[n-1]*G
		for i, j := 0, count-1; i < count; i, j = i+1, j-1 {
			// TODO : make sure that s is unique
			scalars[j], _ = rand.Int(rand.Reader, big.NewInt(10000))
			bases[i] = g.zero()
			g.mulScalar(bases[i], one, scalars[j])
		}

		// expected
		//  S[n-1]*P[1], S[n-2]*P[2] ... S[0]*P[n-1]
		expected, tmp := g.zero(), g.zero()
		for i := 0; i < count; i++ {
			g.mulScalar(tmp, bases[i], scalars[i])
			g.add(expected, expected, tmp)
		}
		result := g.zero()
		g.multiExp(result, bases, scalars)
		if !g.equal(expected, result) {
			t.Fatalf("bad multi-exponentiation")
		}
	})
}

func BenchmarkMNT4753PairingApi1Pair(t *testing.B) {
	in, err := hex.DecodeString("095f01c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db117e776f218059db80f0da5cb537e38685acce9767254a4638810719ac425f0e39d54522cdd119f5e9063de245e8001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000201373684a8c9dcae7a016ac5d7748d3313cd8e39051c596560835df0c9e50a5b59b882a92c78dc537e51a16703ec9855c77fc3d8bb21c8d68bb8cfb9db4b8c8fba773111c36c8b1b4e8f1ece940ef9eaad265458e06372009c9a0491678ef4600001c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db26c5c28c859a99b3eebca9429212636b9dff97634993aa4d6c381bc3f0057974ea099170fa13a4fd90776e240000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d30015474b1d641a3fd86dcbcee5dcda7fe51852c8cbe26e600733b714aa43c31a66b0344c4e2c428b07a7713041ba180000130015474b1d641a3fd86dcbcee5dcda7fe51852c8cbe26e600733b714aa43c31a66b0344c4e2c428b07a7713041ba17fff0101010101013b42397c8b004d06f0e98fbc12e8ee65adefcdba683c5630e6b58fb69610b02eab1d43484ddfab28213098b562d799243fb14330903aa64878cfeb34a45d1285da665f5c3f37eb76b86209dcd081ccaef03e65f33d490de480bfee06db00e3eb479d308664381e7942d6c522c0833f674296169420f1dd90680d0ba6686fc27549d52e4292ea5d611cb6b0df32545b07f281032d0a71f8d485e6907766462e17e8dd55a875bd36fe4cd42cac31c0629fb26c333fe091211d0561d10e00f1b7155ed4e903332835a5de0f327aa11b2d74eb8627e3a7b833be42c11d044b5cf0ae49850eeb07d90c77c67256474b2febf924aca0bfa2e4dacb821c91a04fd0165ac8debb2fc1e763a5c32c2c9f572caa85a91c5243ec4b2981af890400d49c264ec663e731713182a88907b8e979ced82ca592777ad052ec5f4b95dc78dc2010d74f82b9e6d066813ed67f3af1de0d5d425da7a19916cf103f102adf5f95b6b62c24c7d186d60b4a103e157e5667038bb2e828a3374d6439526272004b0e2fef08096ebbaddd2d7f288c4acf17b2267e21dc5ce0f925cd5d02209e34d8b69cc94aef5d90af34d3cd98287ace8f1162079cd2d3d7e6c6c2c073c24a359437e75638a1458f4b2face11f8d2a5200b14d6f9dd0fdd407f04be620ee00bc1925e7fcb64f6f8697cd5e45fae22f5688e51b30bd984c0acdc67d2962520e80d31966e3ec477909ecca358be2eee53c75f55a6f7d9660dd6f3d4336ad50e8bfa5375791d73b863d59c422c3ea006b013e7afb186f2eaa9df68f4d6098")
	if err != nil {
		t.Fatal(err)
	}
	api := new(API)
	for i := 0; i < t.N; i++ {
		api.Run(in)
	}
}
func BenchmarkMNT4753PairingApi4Pair(t *testing.B) {
	in, err := hex.DecodeString("095f01c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db117e776f218059db80f0da5cb537e38685acce9767254a4638810719ac425f0e39d54522cdd119f5e9063de245e8001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000201373684a8c9dcae7a016ac5d7748d3313cd8e39051c596560835df0c9e50a5b59b882a92c78dc537e51a16703ec9855c77fc3d8bb21c8d68bb8cfb9db4b8c8fba773111c36c8b1b4e8f1ece940ef9eaad265458e06372009c9a0491678ef4600001c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db26c5c28c859a99b3eebca9429212636b9dff97634993aa4d6c381bc3f0057974ea099170fa13a4fd90776e240000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d30015474b1d641a3fd86dcbcee5dcda7fe51852c8cbe26e600733b714aa43c31a66b0344c4e2c428b07a7713041ba180000030015474b1d641a3fd86dcbcee5dcda7fe51852c8cbe26e600733b714aa43c31a66b0344c4e2c428b07a7713041ba17fff0101010401013b42397c8b004d06f0e98fbc12e8ee65adefcdba683c5630e6b58fb69610b02eab1d43484ddfab28213098b562d799243fb14330903aa64878cfeb34a45d1285da665f5c3f37eb76b86209dcd081ccaef03e65f33d490de480bfee06db00e3eb479d308664381e7942d6c522c0833f674296169420f1dd90680d0ba6686fc27549d52e4292ea5d611cb6b0df32545b07f281032d0a71f8d485e6907766462e17e8dd55a875bd36fe4cd42cac31c0629fb26c333fe091211d0561d10e00f1b7155ed4e903332835a5de0f327aa11b2d74eb8627e3a7b833be42c11d044b5cf0ae49850eeb07d90c77c67256474b2febf924aca0bfa2e4dacb821c91a04fd0165ac8debb2fc1e763a5c32c2c9f572caa85a91c5243ec4b2981af890400d49c264ec663e731713182a88907b8e979ced82ca592777ad052ec5f4b95dc78dc2010d74f82b9e6d066813ed67f3af1de0d5d425da7a19916cf103f102adf5f95b6b62c24c7d186d60b4a103e157e5667038bb2e828a3374d6439526272004b0e2fef08096ebbaddd2d7f288c4acf17b2267e21dc5ce0f925cd5d02209e34d8b69cc94aef5d90af34d3cd98287ace8f1162079cd2d3d7e6c6c2c073c24a359437e75638a1458f4b2face11f8d2a5200b14d6f9dd0fdd407f04be620ee00bc1925e7fcb64f6f8697cd5e45fae22f5688e51b30bd984c0acdc67d2962520e80d31966e3ec477909ecca358be2eee53c75f55a6f7d9660dd6f3d4336ad50e8bfa5375791d73b863d59c422c3ea006b013e7afb186f2eaa9df68f4d609801013b42397c8b004d06f0e98fbc12e8ee65adefcdba683c5630e6b58fb69610b02eab1d43484ddfab28213098b562d799243fb14330903aa64878cfeb34a45d1285da665f5c3f37eb76b86209dcd081ccaef03e65f33d490de480bfee06db00e0dae5f5938aabea71a9ac0c088af77657e918f999593dc60b69048acccc9f8df6b09ecbbf4b06e6c77884a446be7ec38c6eff970270ad9d14d1456cedc102149ed18d94fefbedcad9734deff944b1dcf1b27a70de5f7dff42c11efcaef300f1b7155ed4e903332835a5de0f327aa11b2d74eb8627e3a7b833be42c11d044b5cf0ae49850eeb07d90c77c67256474b2febf924aca0bfa2e4dacb821c91a04fd0165ac8debb2fc1e763a5c32c2c9f572caa85a91c5243ec4b2981af890400d49c264ec663e731713182a88907b8e979ced82ca592777ad052ec5f4b95dc78dc2010d74f82b9e6d066813ed67f3af1de0d5d425da7a19916cf103f102adf5f95b6b62c24c7d186d60b4a103e157e5667038bb2e828a3374d6439526272004b0e2fef08096ebbaddd2d7f288c4acf17b2267e21dc5ce0f925cd5d02209e34d8b69cc94aef5d90af34d3cd98287ace8f1162079cd2d3d7e6c6c2c073c24a359437e75638a1458f4b2face11f8d2a5200b14d6f9dd0fdd407f04be620ee00bc1925e7fcb64f6f8697cd5e45fae22f5688e51b30bd984c0acdc67d2962520e80d31966e3ec477909ecca358be2eee53c75f55a6f7d9660dd6f3d4336ad50e8bfa5375791d73b863d59c422c3ea006b013e7afb186f2eaa9df68f4d609801013b42397c8b004d06f0e98fbc12e8ee65adefcdba683c5630e6b58fb69610b02eab1d43484ddfab28213098b562d799243fb14330903aa64878cfeb34a45d1285da665f5c3f37eb76b86209dcd081ccaef03e65f33d490de480bfee06db00e3eb479d308664381e7942d6c522c0833f674296169420f1dd90680d0ba6686fc27549d52e4292ea5d611cb6b0df32545b07f281032d0a71f8d485e6907766462e17e8dd55a875bd36fe4cd42cac31c0629fb26c333fe091211d0561d10e00f1b7155ed4e903332835a5de0f327aa11b2d74eb8627e3a7b833be42c11d044b5cf0ae49850eeb07d90c77c67256474b2febf924aca0bfa2e4dacb821c91a04fd0165ac8debb2fc1e763a5c32c2c9f572caa85a91c5243ec4b2981af890400d49c264ec663e731713182a88907b8e979ced82ca592777ad052ec5f4b95dc78dc2010d74f82b9e6d066813ed67f3af1de0d5d425da7a19916cf103f102adf5f95b6b62c24c7d186d60b4a103e157e5667038bb2e828a3374d6439526272004b0e2fef08096ebbaddd2d7f288c4acf17b2267e21dc5ce0f925cd5d02209e34d8b69cc94aef5d90af34d3cd98287ace8f1162079cd2d3d7e6c6c2c073c24a359437e75638a1458f4b2face11f8d2a5200b14d6f9dd0fdd407f04be620ee00bc1925e7fcb64f6f8697cd5e45fae22f5688e51b30bd984c0acdc67d2962520e80d31966e3ec477909ecca358be2eee53c75f55a6f7d9660dd6f3d4336ad50e8bfa5375791d73b863d59c422c3ea006b013e7afb186f2eaa9df68f4d609801013b42397c8b004d06f0e98fbc12e8ee65adefcdba683c5630e6b58fb69610b02eab1d43484ddfab28213098b562d799243fb14330903aa64878cfeb34a45d1285da665f5c3f37eb76b86209dcd081ccaef03e65f33d490de480bfee06db00e0dae5f5938aabea71a9ac0c088af77657e918f999593dc60b69048acccc9f8df6b09ecbbf4b06e6c77884a446be7ec38c6eff970270ad9d14d1456cedc102149ed18d94fefbedcad9734deff944b1dcf1b27a70de5f7dff42c11efcaef300f1b7155ed4e903332835a5de0f327aa11b2d74eb8627e3a7b833be42c11d044b5cf0ae49850eeb07d90c77c67256474b2febf924aca0bfa2e4dacb821c91a04fd0165ac8debb2fc1e763a5c32c2c9f572caa85a91c5243ec4b2981af890400d49c264ec663e731713182a88907b8e979ced82ca592777ad052ec5f4b95dc78dc2010d74f82b9e6d066813ed67f3af1de0d5d425da7a19916cf103f102adf5f95b6b62c24c7d186d60b4a103e157e5667038bb2e828a3374d6439526272004b0e2fef08096ebbaddd2d7f288c4acf17b2267e21dc5ce0f925cd5d02209e34d8b69cc94aef5d90af34d3cd98287ace8f1162079cd2d3d7e6c6c2c073c24a359437e75638a1458f4b2face11f8d2a5200b14d6f9dd0fdd407f04be620ee00bc1925e7fcb64f6f8697cd5e45fae22f5688e51b30bd984c0acdc67d2962520e80d31966e3ec477909ecca358be2eee53c75f55a6f7d9660dd6f3d4336ad50e8bfa5375791d73b863d59c422c3ea006b013e7afb186f2eaa9df68f4d6098")
	if err != nil {
		t.Fatal(err)
	}
	api := new(API)
	for i := 0; i < t.N; i++ {
		api.Run(in)
	}
}

func BenchmarkMnt4753SubGroupCheck(t *testing.B) {
	byteLen := 96
	modulusBytes := bytes_(byteLen, "0x1c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db117e776f218059db80f0da5cb537e38685acce9767254a4638810719ac425f0e39d54522cdd119f5e9063de245e8001")
	groupBytes := bytes_(byteLen, "0x1c4c62d92c41110229022eee2cdadb7f997505b8fafed5eb7e8f96c97d87307fdb925e8a0ed8d99d124d9a15af79db26c5c28c859a99b3eebca9429212636b9dff97634993aa4d6c381bc3f0057974ea099170fa13a4fd90776e240000001")
	f := newField(modulusBytes)

	// G1
	a, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x02"))
	if err != nil {
		t.Fatal(err)
	}

	b, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x1373684a8c9dcae7a016ac5d7748d3313cd8e39051c596560835df0c9e50a5b59b882a92c78dc537e51a16703ec9855c77fc3d8bb21c8d68bb8cfb9db4b8c8fba773111c36c8b1b4e8f1ece940ef9eaad265458e06372009c9a0491678ef4"))
	if err != nil {
		t.Fatal(err)
	}

	g1, err := newG1(f, nil, nil, groupBytes)
	if err != nil {
		panic(err)
	}
	f.copy(g1.a, a)
	f.copy(g1.b, b)

	fq2, err := newFq2(f, nil)
	if err != nil {
		panic(err)
	}

	nonResidue, err := f.newFieldElementFromBytes(bytes_(byteLen, "0x0d")) // decimal 13
	if err != nil {
		panic(err)
	}
	f.copy(fq2.nonResidue, nonResidue)
	fq2.calculateFrobeniusCoeffs()

	fq4, err := newFq4(fq2, nil)
	if err != nil {
		panic(err)
	}
	fq4.nonResidue = fq2.zero()
	// fq4.f.f.copy(fq4.nonResidue[0], fq2.nonResidue)
	fq4.calculateFrobeniusCoeffs()

	// G2
	g2, err := newG22(fq2, nil, nil, groupBytes)
	if err != nil {
		panic(err)
	}
	// y^2 = x^3 + b/(9+u)
	twist, twist2, twist3 := fq2.newElement(), fq2.newElement(), fq2.newElement()
	f.copy(twist[0], f.zero)
	f.copy(twist[1], f.one)
	fq2.square(twist2, twist)
	fq2.mul(twist3, twist2, twist)
	fq2.mulByFq(g2.a, twist2, a)
	fq2.mulByFq(g2.b, twist3, b)

	generatorBytes := bytes_(byteLen,
		"0xf1b7155ed4e903332835a5de0f327aa11b2d74eb8627e3a7b833be42c11d044b5cf0ae49850eeb07d90c77c67256474b2febf924aca0bfa2e4dacb821c91a04fd0165ac8debb2fc1e763a5c32c2c9f572caa85a91c5243ec4b2981af8904",
		"0xd49c264ec663e731713182a88907b8e979ced82ca592777ad052ec5f4b95dc78dc2010d74f82b9e6d066813ed67f3af1de0d5d425da7a19916cf103f102adf5f95b6b62c24c7d186d60b4a103e157e5667038bb2e828a3374d6439526272",
		"0x4b0e2fef08096ebbaddd2d7f288c4acf17b2267e21dc5ce0f925cd5d02209e34d8b69cc94aef5d90af34d3cd98287ace8f1162079cd2d3d7e6c6c2c073c24a359437e75638a1458f4b2face11f8d2a5200b14d6f9dd0fdd407f04be620ee",
		"0xbc1925e7fcb64f6f8697cd5e45fae22f5688e51b30bd984c0acdc67d2962520e80d31966e3ec477909ecca358be2eee53c75f55a6f7d9660dd6f3d4336ad50e8bfa5375791d73b863d59c422c3ea006b013e7afb186f2eaa9df68f4d6098",
	)

	one, err := g2.fromBytes(generatorBytes)
	if err != nil {
		panic(err)
	}
	if !g2.isOnCurve(one) {
		panic("q is not on curve\n")
	}

	e := g2.newPoint()
	for i := 0; i < t.N; i++ {
		g2.checkCorrectSubGroup(e, one)
	}
}
