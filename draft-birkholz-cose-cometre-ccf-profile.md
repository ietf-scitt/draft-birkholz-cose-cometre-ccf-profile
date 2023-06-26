---
title: A CoMETRE Profile and Tree Algorithm for the Confidential Consortium Framework
abbrev: CoMTRE CFF Profile
docname: draft-birkholz-cose-cometre-ccf-profile-latest
stand_alone: true
ipr: trust200902
area: Security
wg: TBD
kw: Internet-Draft
cat: std
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author:
- name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- name: Antoine Delignat-Lavaud
  organization: Microsoft Research
  street: 21 Station Road
  code: 'CB1 2FB'
  city: Cambridge
  email: antdl@microsoft.com
  country: UK
- name: Cedric Fournet
  organization: Microsoft Research
  street: 21 Station Road
  code: 'CB1 2FB'
  city: Cambridge
  email: fournet@microsoft.com
  country: UK

normative:
  RFC9162: certificate-transparency-v2

informative:
  I-D.draft-steele-cose-merkle-tree-proofs: COMTRE

--- abstract

This document describes a tree algorithm for COSE Signed Merkle Tree Proofs specifically designed for implementations that rely on Trusted Execution Environments (TEEs) to make the
ledger tamper-proof.

--- middle

# Introduction

The Concise Encoding of Signed Merkle Tree Proofs (CoMeTre) {{-COMTRE}} defines a standard format for carrying COSE-encoded Merkle Tree proofs and the associated signed root value.
This is helpful to pove to a verifier that a given serializable element is recorded at a given index in the Merkle Tree, or to prove that a tree is an extension of another.

In this document, we describe how to verify such CoMeTre proofs for a new type of trees associated with the Confidential Consortium Framework (CCF). Compared to {{-certificate-transparency-v2}}, the leaves of CCF trees carry additional opaque infomation that is used to verify that elements are only written by the Trusted Execution Environment,
which addresses the persistance of committed transactions that happen between new signatures of
the Merkle Tree root.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Description of the CCF Tree Algorithm

Recall the definition of CoMeTre inclusion proofs, which are parametrized by 3 CBOR data types that are specific to the Tree Algorithm:

~~~~ cddl
signed-inclusion-proof = [
  signed-inclusion-proof: bstr .cbor smtr ; the payload is a merkle root, as described by the tree algorithm, and is detached.
  inclusion-proof: bstr .cbor CCF-inclusion-proof; the inclusion-proof, as described in the tree algorithm
  leaf: bstr .cbor CCF-leaf ; the leaf, as described in the tree algorithm
]
~~~~

This document defines the `CCF-feaf` and `CCF-inclusion-proof` CBOR types. The signed Merkle Root data type `smtr` is the same as in {{-COMTRE}} but MUST set the protected header parameter carrying the identifier of the tree algorithm, `tree_alg`, to the value TBD_1.

## Tree Shape

The input of the Merkle Tree Hash (MTH) function is a list of n bytestrings, written D_n = \{d\[0\], d\[1\], ..., d\[n-1\]\}. The output is a single HASH_SIZE bytestring, also called the tree root hash.

This function is defined as follows:

The hash of an empty list is the hash of an empty string:

~~~
MTH({}) = HASH().
~~~

The hash of a list with one entry (also known as a leaf hash) is:

~~~
MTH({d[0]}) = HASH(d[0]).
~~~

For n > 1, let k be the largest power of two smaller than n (i.e., k < n <= 2k). The Merkle Tree Hash of an n-element list D_n is then defined recursively as:

~~~
MTH(D_n) = HASH(MTH(D[0:k]) || MTH(D[k:n])),
~~~

where:

- \|\| denotes concatenation
- : denotes concatenation of lists
- D\[k1:k2\] = D'_(k2-k1) denotes the list \{d'\[0\] = d\[k1\], d'\[1\] = d\[k1+1\], ..., d'\[k2-k1-1\] = d\[k2-1\]\} of length (k2 - k1).

## Leaf Components

Each leaf in a CCF Merkle Tree carries the following components:

~~~
CCF-leaf = [
  internal-hash: bstr ; a string of HASH_SIZE bytes;
  internal-data: bstr; a string of at most 1024 bytes; and
  data_hash: bstr ; the serialization of the element stored at this leaf.
]
~~~

The `internal_hash` and `internal_data` bytestrings are internal to the CCF implementation. Similarly, the auxiliary ledger entries are internal to CCF. They are opaque to receipt Verifiers, but they commit the TS to the whole ledger contents and may be used for additional, CCF-specific auditing.

## Signed Inclusion Proof Format

CCF inclusion proofs consist of a list of digests tagged with a single left-or-right bit.

~~~
inclusion_proof: [+ proof-element],

proof-element = [
  left: bool
  hash: bstr
]
~~~

## Inclusion Proof Verification Algorithm

When a client has received an inclusion proof and wishes to verify inclusion of a signed inclusion proof:

~~~
compute_root(leaf, proof):
  h := leaf.internal-hash
       || HASH(leaf.internal-data)
       || leaf.data-hash

  for [left, hash] in proof:
      h := HASH(hash + h) if left
           HASH(h + hash) else
  return h

verify_proof(smtr):
  h = compute_root(smtr.leaf, smtr.inclusion-proof)
  return verif_cose(smtr.signed-inclusion-proof, h)
~~~

## Signed Consistency Proof

TBD

# Privacy Considerations

Privacy Considerations

# Security Considerations

Security Considerations

# IANA Considerations

## Additions to Existing Registries

### Tree Algorithms {#tree-alg-registry}

This document requests IANA to add the following new value to the 'Tree Algorithms' registry:


* Identifier: TBD_1
* Tree Algorithm: ccf_ledger
* Reference: This document

--- back

# Attic

Not ready to throw these texts into the trash bin yet.

