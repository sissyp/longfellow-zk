// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_SCAN_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_SCAN_H_

#include <stddef.h>

#include <vector>

namespace proofs {
template <class Logic>
class Scan {
 public:
  using EltW = typename Logic::EltW;
  using BitW = typename Logic::BitW;

  explicit Scan(const Logic& l) : l_(l) {}

  /* Segmented prefix add, equivalent to this code:

       s = 0;
       for (size_t i = 0; i < n; ++i) {
         if (S[i]) {
           s = A[i];
         } else {
           s += ds[i];
         }
         B[i] = s;
       }
  */
  void add(size_t n, EltW B[/*n*/], const BitW S[/*n*/], const EltW A[/*n*/],
           const EltW ds[/*n*/]) {
    const Logic& L = l_;  // shorthand
    std::vector<BitW> S1(n);
    for (size_t i = 0; i < n; ++i) {
      S1[i] = S[i];
      B[i] = L.mux(&S[i], &A[i], ds[i]);
    }
    scan_add(0, n, S1.data(), B);
  }

  // unsegmented variant of add(), assume S[i] = false
  void add(size_t n, EltW B[/*n*/], const EltW ds[/*n*/]) {
    for (size_t i = 0; i < n; ++i) {
      B[i] = ds[i];
    }
    scan_add(0, n, B);
  }

 private:
  const Logic& l_;

  void scan_add(size_t i0, size_t i1, BitW S[/*n*/], EltW B[/*n*/]) {
    if (i1 - i0 > 1) {
      const Logic& L = l_;  // shorthand
      size_t im = i0 + (i1 - i0) / 2;
      scan_add(i0, im, S, B);
      scan_add(im, i1, S, B);

      size_t j = im - 1;
      for (size_t i = im; i < i1; ++i) {
        // special case of B[i] = S[i] ? B[i] : B[i] + B[j]
        // coded as B[i] = B[i] + (~S[i] * B[j])
        auto ns = L.lnot(S[i]);
        auto ns_bj = L.lmul(&ns, B[j]);
        B[i] = L.add(&B[i], ns_bj);
        S[i] = L.lor(&S[i], S[j]);
      }
    }
  }

  // unsegmented
  void scan_add(size_t i0, size_t i1, EltW B[/*n*/]) {
    if (i1 - i0 > 1) {
      const Logic& L = l_;  // shorthand
      size_t im = i0 + (i1 - i0) / 2;
      scan_add(i0, im, B);
      scan_add(im, i1, B);

      size_t j = im - 1;
      for (size_t i = im; i < i1; ++i) {
        B[i] = L.add(&B[j], B[i]);
      }
    }
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_SCAN_H_
