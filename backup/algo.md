Algorithm 1: Probabilistic Disassembling

Input:    B  - binary indexed by address
          H  - probabilistic hints, denoted by a mapping from
               an address to a prior probability

Output:   P[i] - posterior probability of an address i denoting
                 a true positive instruction

Variable: D[i]  - probability of address i being data byte
          RH[i] - the set of hints, denoted by a set of addresses,
                  that reach an address i

 1: for each address i in B do
 2:     if invalidInstr(i) then
 3:         D[i] ← 1.0
 4:     else
 5:         D[i] ← ⊥
 6:     RH[i] ← {}
 7: fixed_point ← false
 8: while !fixed_point do
 9:     fixed_point ← true

                                ▷ Forward propagation of hints (Step I)
10:     for each address i from start of B to end do
11:         if D[i] ≡ 1.0 then
12:             continue
13:         if H[i] ≠ ⊥ and i ∉ RH[i] then
14:             RH[i] ← RH[i] ∪ {i}
15:             D[i]
