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
  I-D.steele-cose-merkle-tree-proofs: COMTRE

--- abstract

This document defines a new verifiable data structure type for COSE Signed Merkle Tree Proofs specifically designed for implementations that rely on Trusted Execution Environments (TEEs) to provide stronger tamper-evidence guarantees.

--- middle

# Introduction

The Concise Encoding of Signed Merkle Tree Proofs (CoMeTre) {{-COMTRE}} defines a common framework for defining different types of proofs, such as proof of inclusion, about verifiable data structures (also abbreviated as "logs" in this document). For instance, inclusion proofs guarantee to a verifier that a given serializable element is recorded at a given state of the log, while consistency proofs are used to establish that an inclusion proof is still consistent with the new state of the log at a later time.

In this document, we define a new type of log, associated with the Confidential Consortium Framework (CCF) ledger. Compared to {{-certificate-transparency-v2}}, the leaves of CCF trees carry additional opaque information that is used to verify that elements are only written by the Trusted Execution Environment, which addresses the persistence of committed transactions that happen between new signatures of the Merkle Tree root.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Description of the CCF Ledger Verifiable Data Structure

This documents extends the verifiable data structure registry of {{-COMTRE}} with the following value:

| Identifier            | Algorithm | Reference
|---
|TBD_1 | CCF_LEDGER     | This document
{: #verifiable-data-structure-values align="left" title="Verifiable Data Structure Algorithms"}

## Tree Shape

The input of the Merkle Tree Hash (MTH) function is a list of n byte strings, written D_n = \{d\[0\], d\[1\], ..., d\[n-1\]\}. The output is a single HASH_SIZE byte string, also called the Merkle root hash.

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

Each leaf in a CCF ledger carries the following components:

~~~
CCF-leaf = [
  internal-hash: bstr ; a string of HASH_SIZE bytes;
  internal-data: bstr; a string of at most 1024 bytes; and
  data_hash: bstr ; the serialization of the element stored at this leaf.
]
~~~

The `internal_hash` and `internal_data` byte strings are internal to the CCF implementation. Similarly, the auxiliary tree entries are internal to CCF. They are opaque to receipt Verifiers, but they commit the TS to the whole tree contents and may be used for additional, CCF-specific auditing.

# CCF Inclusion Proofs

CCF inclusion proofs consist of a list of digests tagged with a single left-or-right bit.

~~~
CCF-inclusion-proof: [+ proof-element],

proof-element = [
  left: bool
  hash: bstr
]
~~~

Unlike some other tree algorithms, the index of the element in the tree is not explicit in the inclusion proof, but the list of left-or-right bits can be treated as the binary decomposition of the index, from the least significant (leaf) to the most significant (root).

## CCF Inclusion Proof Signature

The proof signature for a CCF inclusion proof is a COSE signature (encoded with the `COSE_Sign1` CBOR type) which includes the following additional requirements for protected and unprotected headers. Please note that there may be additional headers defined by the application.

The protected headers for the CCF inclusion proof signature MUST include the following:

* `verifiable-data-structure: int/tstr`. This header MUST be set to the verifiable data structure algorithm identifier for `ccf-ledger` (TBD_1).
* `proof-type: int`. This header MUST be set to the value of the `inclusion` proof type in the IANA registry of Verifiable Data Structure Proof Type.

The unprotected header for a CCF inclusion proof signature MUST include the following:

* `inclusion-proof: bstr .cbor CCF-inclusion-proof`. This contains the serialized CCF inclusion proof, as defined above.
* `leaf` (label TBD_2): `bstr .cbor CCF-leaf`. This contains the CCF-specific serialization of the leaf element

The payload of the signature is the CCF ledger Markle root digest, and MUST be detached in order to force verifiers to recompute the root from the inclusion proof in the unprotected header. This provides a safeguard against implementation errors that use the payload of the signature but do not recompute the root from the inclusion proof.

## Inclusion Proof Verification Algorithm

CCF uses the following algorithm to recompute the payload of the signature based on the `inclusion-proof` header:

~~~
compute_root(leaf, proof):
  h := leaf.internal-hash
       || HASH(leaf.internal-data)
       || leaf.data-hash

  for [left, hash] in proof:
      h := HASH(hash + h) if left
           HASH(h + hash) else
  return h

verify_inclusion_proof(signed_proof):
  leaf := signed_proof.unprotected_headers[LEAF_LABEL] or fail
  proof := signed_proof.unprotected_headers[INCLUSION_PROOF_LABEL] or fail
  payload := compute_root(leaf, proof)
  return verif_cose_detached(signed_proof, payload)
~~~

# Privacy Considerations

Privacy Considerations

# Security Considerations

Security Considerations

# IANA Considerations

## Additions to Existing Registries

### COSE Header Parameters registry

This document requests IANA to add the following new value to the 'COSE Header Parameters' registry:

* Label: TBD_2
* Value type: `bstr`
* Reference: This document

### Tree Algorithms {#tree-alg-registry}

This document requests IANA to add the following new value to the 'Tree Algorithms' registry:

* Identifier: TBD_1
* Tree Algorithm: ccf-ledger
* Reference: This document

--- back

# Attic

Not ready to throw these texts into the trash bin yet.

