---
title: A Transaction Ledger Verifiable Structure for COSE Merkle Tree Proofs
abbrev: CoMTRE CFF Ledger
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
  I-D.ietf-cose-merkle-tree-proofs: COMTRE

--- abstract

This document defines a new verifiable data structure type for COSE Signed Merkle Tree Proofs specifically designed for transaction ledgers produced by Trusted Execution Environments (TEEs) to provide stronger tamper-evidence guarantees.

--- middle

# Introduction

The Concise Encoding of Signed Merkle Tree Proofs (CoMeTre) {{-COMTRE}} defines a common framework for defining different types of proofs about verifiable data structures (also abbreviated as "logs" in this document). For instance, inclusion proofs guarantee to a verifier that a given serializable element is recorded at a given state of the log, while consistency proofs are used to establish that an inclusion proof is still consistent with the new state of the log at a later time.

In this document, we define a new type of log, associated with the Confidential Consortium Framework (CCF) ledger. This log carries indexed transaction information in a binary Merkle Tree, where new transactions are appended to the right, so that the binary decomposition of the index of a transaction can be interpreted as the position in the tree if 0 represents the left branch and 1 the right branch.  Compared to {{-certificate-transparency-v2}}, the leaves of CCF trees carry additional opaque information that is used to verify that elements are only written by the Trusted Execution Environment, which addresses the persistence of committed transactions that happen between new signatures of the Merkle Tree root.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Format of CCF Ledger

This documents extends the verifiable data structure registry of {{-COMTRE}} with the following value:

| Name            | Value   | Description | Reference
|---
|CCF_LEDGER_SHA256 | TBD_1 (requested assignment 2) | Historical transaction ledgers, such as the CCF ledger | This document
{: #verifiable-data-structure-values align="left" title="Verifiable Data Structure Algorithms"}

This document defines inclusion proofs and consistency proof formats for CCF ledgers. Verifiers MUST reject all other proof types.

## Merkle Tree Shape

A CCF ledger is a binary Merkle Tree constructed from a hash function H, which is defined from the log type. For instance, the hash function for `CCF_LEDGER_SHA256` is `SHA256`, whose `HASH_SIZE` is 32 bytes.
The Merkle tree encodes an ordered list of `n` transactions T_n = \{T\[0\], T\[1\], ..., T\[n-1\]\}. We define the Merkle Tree Hash (MTH) function, which takes as input a list of serialized transactions (as byte strings), and outputs a single HASH_SIZE byte string called the Merkle root hash, by induction on the list:

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

Each leaf transaction in a CCF ledger carries the following components:

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
CCF-inclusion-proof: [
  leaf: CCF-leaf ;
  path: [+ ccf-proof-element] ;
]

ccf-proof-element = [
  left: bool
  hash: bstr
]
~~~

Unlike some other tree algorithms, the index of the element in the tree is not explicit in the inclusion proof, but the list of left-or-right bits can be treated as the binary decomposition of the index, from the least significant (leaf) to the most significant (root).

## Inclusion Proof Verification Algorithm

CCF uses the following algorithm to validate an inclusion receipt:

~~~
compute_root(proof):
  let h = proof.leaf.internal-hash
       || HASH(proof.leaf.internal-data)
       || proof.leaf.data-hash
  for [left, hash] in proof.path:
      h := HASH(hash + h) if left
           HASH(h + hash) else
  return h

verify_inclusion_receipt(inclusion_receipt):
  let proofs = inclusion_receipt.unprotected_headers[-222] or fail
  let payload = nil
  assert(inclusion_receipt.payload == nil)

  for proof in proofs 
    let root = compute_root(proof)
    if payload = nil then payload := root
    else assert(root == payload)

  # Use the Merkle Root as the detached payload
  return verif_cose(inclusion_receipt, payload)
~~~

# Privacy Considerations

Privacy Considerations

# Security Considerations

Security Considerations

# IANA Considerations

## Additions to Existing Registries

### Tree Algorithms {#tree-alg-registry}

This document requests IANA to add the following new value to the 'COSE Verifiable Data Structures' registry:

* Name: CCF_LEDGER_SHA256
* Value: TBD_1 (requested assignment 2)
* Description: Historical transaction ledgers, such as the CCF ledger
* Reference: This document

--- back

# Attic

Not ready to throw these texts into the trash bin yet.

