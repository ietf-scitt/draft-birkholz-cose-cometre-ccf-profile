---
title: A Transaction Ledger Verifiable Structure for COSE Merkle Tree Proofs
abbrev: CoMTRE CCF Profile
docname: draft-birkholz-cose-cometre-ccf-profile-latest
stand_alone: true
ipr: trust200902
area: Security
wg: TBD
kw: Internet-Draft
cat: std
submissiontype: IETF
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

This document defines a new verifiable data structure type for COSE Signed Merkle Tree Proofs specifically designed for transaction ledgers produced by Trusted Execution Environments (TEEs) to provide stronger tamper-evidence guarantees.

--- middle

# Introduction

The Concise Encoding of Signed Merkle Tree Proofs (CoMeTre) {{-COMTRE}} defines a common framework for defining different types of proofs, such as proof of inclusion, about verifiable data structures (VDS). For instance, inclusion proofs guarantee to a verifier that a given serializable element is recorded at a given state of the VDS, while consistency proofs are used to establish that an inclusion proof is still consistent with the new state of the VDS at a later time.

In this document, we define a new type of VDS, associated with the Confidential Consortium Framework (CCF) ledger. This VDS carries indexed transaction information in a binary Merkle Tree, where new transactions are appended to the right, so that the binary decomposition of the index of a transaction can be interpreted as the position in the tree if 0 represents the left branch and 1 the right branch. Compared to {{-certificate-transparency-v2}}, the leaves of CCF trees carry additional opaque information for the following purposes:

1. To bind the full details of the transaction executed, which is a super-set of what is exposed in the proof and captures internal information details useful for detailed system audit, but not for application purposes.
1. To verify that elements are only written by the Trusted Execution Environment, which addresses the persistence of committed transactions that happen between new signatures of the Merkle Tree root.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Description of the CCF Ledger Verifiable Data Structure

This documents extends the verifiable data structure registry of {{-COMTRE}} with the following value:

| Name | Value | Description | Reference
|---
|CCF_LEDGER_SHA256 | TBD_1 (requested assignment 2) | Historical transaction ledgers, such as the CCF ledger | This document
{: #verifiable-data-structure-values align="left" title="Verifiable Data Structure Algorithms"}

This document defines inclusion proofs for CCF ledgers. Verifiers MUST reject all other proof types

## Merkle Tree Shape

A CCF ledger is a binary Merkle Tree constructed from a hash function H, which is defined from the log type. For instance, the hash function for `CCF_LEDGER_SHA256` is `SHA256`, whose `HASH_SIZE` is 32 bytes.

The Merkle tree encodes an ordered list of `n` transactions T_n = \{T\[0\], T\[1\], ..., T\[n-1\]\}. We define the Merkle Tree Hash (MTH) function, which takes as input a list of serialized transactions (as byte strings), and outputs a single HASH_SIZE byte string called the Merkle root hash, by induction on the list:

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

## Transaction Components

Each leaf in a CCF ledger carries the following components:

~~~
CCF-leaf = [

  ; a string of HASH_SIZE bytes
  internal-transaction-hash: bstr

  ; a string of at most 1024 bytes;
  internal-evidence: bstr

  ; a string of HASH_SIZE bytes
  data-hash: bstr
]
~~~

The `internal-transaction-hash` and `internal-evidence` byte strings are internal to the CCF implementation. They are opaque to receipt Verifiers, but they commit the TS to the whole tree contents and may be used for additional, CCF-specific auditing.

# CCF Inclusion Proofs

CCF inclusion proofs consist of a list of digests tagged with a single left-or-right bit.

~~~
CCF-inclusion-proof: [
  leaf (label TBD_2): CCF-leaf
  path (label TBD_3): [+ ccf-proof-element]
]

ccf-proof-element = [

  ; position of the element
  left: bool

  ; hash of the proof element
  hash: bstr
]
~~~

Unlike some other tree algorithms, the index of the element in the tree is not explicit in the inclusion proof, but the list of left-or-right bits can be treated as the binary decomposition of the index, from the least significant (leaf) to the most significant (root).

## CCF Inclusion Proof Signature

The proof signature for a CCF inclusion proof is a COSE signature (encoded with the `COSE_Sign1` CBOR type) which includes the following additional requirements for protected and unprotected headers. Please note that there may be additional headers defined by the application.

The protected headers for the CCF inclusion proof signature MUST include the following:

* `verifiable-data-structure: int/tstr`. This header MUST be set to the verifiable data structure algorithm identifier for `ccf-ledger` (TBD_1).
* `label: int`. This header MUST be set to the value of the `inclusion` proof type in the IANA registry of Verifiable Data Structure Proof Type (-1).

The unprotected header for a CCF inclusion proof signature MUST include the following:

* `inclusion-proof: bstr .cbor CCF-inclusion-proof`. This contains the serialized CCF inclusion proof, as defined above.

The payload of the signature is the CCF ledger Merkle root digest, and MUST be detached in order to force verifiers to recompute the root from the inclusion proof in the unprotected header. This provides a safeguard against implementation errors that use the payload of the signature but do not recompute the root from the inclusion proof.

## Inclusion Proof Verification Algorithm

CCF uses the following algorithm to validate an inclusion receipt:

~~~
compute_root(proof):
  h := proof.leaf.internal-transaction-hash
       || HASH(proof.leaf.internal-evidence)
       || proof.leaf.data-hash

  for [left, hash] in proof:
      h := HASH(hash + h) if left
           HASH(h + hash) else
  return h

verify_inclusion_receipt(inclusion_receipt):
  let proof = inclusion_receipt.unprotected_headers[INCLUSION_PROOF_LABEL] or fail
  assert(inclusion_receipt.payload == nil)
  let payload = compute_root(proof)

  # Use the Merkle Root as the detached payload
  return verif_cose(inclusion_receipt, payload)
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

* Label: TBD_3
* Value type: `bstr`
* Reference: This document

### Tree Algorithms {#tree-alg-registry}

This document requests IANA to add the following new value to the ''COSE Verifiable Data Structures' registry:

* Name: CCF_LEDGER_SHA256
* Value: TBD_1 (requested assignment 2)
* Description: Historical transaction ledgers, such as the CCF ledger
* Reference: This document

--- back

# Attic

Not ready to throw these texts into the trash bin yet.

