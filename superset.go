package main

import (
	"errors"

	"github.com/knightsc/gapstone"
)

type Instruction struct {
	Address      uint64
	Size         uint8
	Mnemonic     string
	Operands     []string
	Bytes        []byte
	RegsRead     []uint16
	RegsWrite    []uint16
	Groups       []uint8
	BranchTarget *uint64
}

type SuperSet struct {
	Engine       *gapstone.Engine
	BaseAddress  uint64
	Bytes        []byte
	Instructions []Instruction
}

func NewSuperset(bytes []byte, baseAddress uint64) (*SuperSet, error) {
	if len(bytes) == 0 {
		return nil, errors.New("bytes must not be empty")
	}
	engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
	if err != nil {
		return nil, err
	}
	ss := &SuperSet{
		BaseAddress: baseAddress,
		Bytes:       bytes,
		Engine:      engine,
	}
	return ss, nil
}

func (s *SuperSet) Disassemble() {
	for offset, byte := range s.Bytes {
		addr := s.Base_Address + uint64(offset)

	}

}
