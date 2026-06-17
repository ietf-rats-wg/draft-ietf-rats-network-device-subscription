---
title: Attestation Event Stream Subscription
abbrev: RATS YANG Subscription
docname: draft-ietf-rats-network-device-subscription-latest
wg: RATS Working Group
stand_alone: true
ipr: trust200902
stream: IETF
area: Security
kw: Internet-Draft
cat: std
pi:
  toc: 'yes'
  sortrefs: 'yes'
  symrefs: 'yes'

author:
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@ietf.contact
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: E. Voit
  name: Eric Voit
  org: Cisco Systems, Inc.
  abbrev: Cisco
  email: evoit@cisco.com
- ins: W. Pan
  name: Wei Pan
  org: Huawei Technologies
  abbrev: Huawei
  street: 101 Software Avenue, Yuhuatai District
  city: Nanjing, Jiangsu
  region: ''
  code: '210012'
  country: China
  phone: ''
  email: william.panwei@huawei.com

normative:
  RFC6241:
  RFC6242:
  RFC8040:
  RFC8341:
  RFC8446:
  RFC9907:
  RFC3688:
  RFC6020:
  RFC9334: rats-arch
  RFC9683: rats-riv
  RFC9684: charra
  I-D.ietf-rats-reference-interaction-models: rats-models
  RFC8639:
  TPM2.0:
    author:
      org: TCG
    title: "TPM 2.0 Library Specification"
    target: https://trustedcomputinggroup.org/resource/tpm-library-specification/
    seriesinfo:

informative:
  RFC7923:
  RFC8641:
  I-D.birkholz-rats-tuda: TUDA
  KGV:
    author:
      org: TCG
    title: "KGV"
    date: 2003-10
    target: https://trustedcomputinggroup.org/wp-content/uploads/TCG-NetEq-Attestation-Workflow-Outline_v1r9b_pubrev.pdf
    seriesinfo:
  TCG-Glossary:
    author:
      org: TCG
    title: "TCG Glossary Version 1.1"
    date: 2017-05
    target: https://trustedcomputinggroup.org/wp-content/uploads/TCG-Glossary-V1.1-Rev-1.0.pdf
  xml-registry:
    target: https://www.iana.org/assignments/xml-registry/xml-registry.xhtml
    title: IETF XML Registry
  yang-parameters:
    target: https://www.iana.org/assignments/yang-parameters/yang-parameters.xhtml
    title: YANG Parameters

--- abstract

This document defines how to subscribe to YANG Event Streams for Remote Attestation Procedures (RATS).
Specifically, this document defines a YANG module that augments the YANG module for Trusted Platform Module (TPM)-based Challenge-Response Remote Attestation (CHARRA), enabling subscription to RATS Conceptual Messages of the Evidence type and auxiliary Event Logs as part of that Evidence.
The module defined requires at least one Trusted Platform Module (TPM) 1.2 or TPM 2.0 (or equivalent hardware implementation providing the same protected capabilities as a TPM) must be available on the Attester on which the YANG server is running.

--- middle

# Introduction

{{-rats-riv}} and {{-charra}} define the operational prerequisites and a YANG Model for acquiring Evidence from a network device containing at least one TPM 1.2 or TPM 2.0 (or equivalent hardware implementations providing the same protected capabilities {{TCG-Glossary}} as a TPM).
However, these documents are based on the challenge-response interaction model (CHARRA in {{Section 7.1 of -rats-models}}), which has limitations.
One such limitation is that it is the responsibility of a Verifier to request signed Evidence from a separate Attester containing a TPM.
This means that the interval between a security-relevant change event occurring and the event becoming visible to the interested RATS entities, such as Verifiers or a Relying Parties, can be unacceptably long.
It is common to convey Conceptual Messages ad-hoc or periodically via requests.
As new technologies emerge, some of these solutions require Conceptual Messages to be conveyed from one RATS entity to another without the need for continuous polling.
Subscription to YANG Notifications {{RFC8639}} provides a set of standardized tools to facilitate these emerging requirements.
This memo specifies a YANG augmentation for subscribing to YANG-modelled remote attestation Evidence, as defined in {{-charra}}.

Essentially, the limitation of poll-based interactions has two adverse effects:

1. Conceptual Messages are not streamed to interested consumers of information (e.g., Verifiers or Relying Parties) as soon as they are generated.

2. Even if they were streamed, the freshness of Conceptual Messages cannot be appraised in every scenario.
This is particularly important for Conceptual Messages, such as Evidence, that depend heavily on freshness.

This specification addresses the first adverse effect by enabling consumers of Conceptual Messages (subscribers) to request a continuous stream of new or updated Conceptual Messages via an {{RFC8639}} subscription to an \<attestation\> Event Stream.
This new Event Stream is defined in this document and is provided by the producer of Conceptual Messages (the publisher).
As covered by this document, via a Verifier's subscription to an Attester's Evidence, the Attester will continuously stream a requested set of freshly generated Evidence to the subscribing Verifier.
For example, when a network device's Evidence changes following events such as booting, updating, control unit failover, plugging in or out of forwarding units, an attack, or certificate lifetime change, the network device will generate fresh Evidence available to the subscribing Verifier.

The second adverse effect stems from the use of nonces in the challenge-response interaction model {{Section 7.1 of -rats-models}} realized in {{-charra}}.
According to {{-charra}}, an Attester must wait for a new nonce from a Verifier before generating a new TPM Quote.
To address delays resulting from this wait, this specification allows freshness to be asserted asynchronously via the streaming attestation interaction model {{-rats-models}}.
To convey a RATS Conceptual Message, an initial nonce is provided when subscribing to an Event Stream.

There are several options to populate or refresh the nonce value provided by the initial subscription.
All of these methods are out-of-band of an established subscription to YANG Notifications.
Two alternative methods are taken into account by this document:

1. A central provider supplies new, fresh nonces (e.g., via a Handle Provider that distributes Epoch IDs to all entities in a domain as described in {{-rats-arch}} and as facilitated by the Uni-Directional Remote Attestation described in {{Section 7.2 of -rats-models}}), or

2. A nonce can be updated by -- potentially periodically or ad-hoc -- sending out-of-band TPM Quote requests as facilitated by {{-charra}}.

Both approaches assume that clock drift can occur between the entities involved.
Consequently, other conditions arising in different application scenarios ought to be considered in the same way. For example, the time of Claims collection ought to be taken into account as it potentially impacts the freshness of Evidence.

The scope of this document is limited to the removal of the two adverse effects described when using the specified YANG augmentation.
In essence, the YANG augmentation enables RATS Verifiers to maintain a continuous appraisal procedure of verifiably fresh Attester Evidence without relying on continuous polling.

# Terminology

The following terms are imported from {{-rats-arch}}: Attester, Conceptual Message, Evidence, Relying Party, and Verifier.  Also imported are the time definitions time(VG), time(NS), time(EG), time(RG), and time(RA) from that document's Appendix A.  The following terms are imported from {{RFC8639}}: Event Stream, Subscription, Publisher, Event Stream Filter, Dynamic Subscription.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Operational Model

{{-rats-riv}} describes the conveyance of TPM-based Evidence from a Verifier to an Attester using the CHARRA interaction model {{Section 7.1 of -rats-models}}. The operational model and corresponding sequence diagram described in this section is based on {{-charra}}. The basis for interoperability required for additional types of Event Streams is covered in {{otherstreams}}. The following subsection focuses on subscription to YANG Notifications to the \<attestation\> Event Stream.

## Sequence Diagrams

This section illustrates the subscription interaction model by mapping terms from {{-rats-models}} and illustrating timing consideration based on Figure 3 of {{-rats-riv}}.
Both sequence diagrams {{term-sequence}} and {{time-sequence}} highlight TPM-specific aspects and the Dynamic Subscription (as specified in {{RFC8639}}) to an \<attestation\> Event Stream.
The contents of the \<attestation\> Event Stream are defined below within {{attestationstream}}.

### Terminology Mapping

The terms defined in {{-charra}} are mapped to the model described in {{Section 7.3.1 of -rats-models}} (Streaming Remote Attestation without a Broker) to produce the sequence diagram {{term-sequence}}.

The terminology mapping is as follows:

* `handle` is substituted with `nonce`, a nonce generated by the Verifier. This is a nonce-value byte string, obtained from either the tpm12-challenge-response-attestation RPC or the tpm20-challenge-response-attestation RPC, as specified in {{-charra}}. Hence, in this case, a 'nonce' value is populated out of band and can be used more than once within the scope of a subscription, based on local policies that enforce freshness requirements (see definition of handle in {{Section 6 of -rats-models}}).

* `attEnvIDs` is substituted with `TpmName`, a TPM "name" text string selected from the `tpms` Container, as specified in {{-charra}}

* `claimsSelection` is substituted with `PcrSelection`, an optional "pcr-index" from either the tpm12-challenge-response-attestation RPC or the tpm20-challenge-response-attestation RPC as specified in {{-charra}}. If none of the TPM's Platform Configration Registers (PCR) are selected, all PCR banks are returned.

* `claims` is substituted with `PcrQuotes`, which is the "output" of either the tpm12-challenge-response-attestation RPC or the tpm20-challenge-response-attestation RPC, as specified in {{-charra}}. Unlike event logs, there is no delta to a previous iteration of PCR Quotes during a subscription; all new (selected) Quotes are conveyed as fresh Evidence.

* `eventLogs` represents "system-event-logs" that are in the "output" of the log-retrieval RPC, as defined in {{-charra}}.

* `eventLogsDelta` represents "system-event-logs" as specified in the "output" of the log-retrieval RPC as defined in {{-charra}} where the "output" is limited as if the "input" were parameterized via an index type (last-entry, index, timestamp) set to the last event in the previously conveyed `eventLogs`.

~~~~ aasvg
.----------.                                .--------------------------.
| Attester |                                | Verifier / Relying Party |
'----+-----'                                '---------------------+----'
     |                                                            |
 .--------[loop]------------------------------------------------------.
|    |                                                            |    |
| =========================[Nonce Generation]========================= |
|    |                                                            |    |
|    |                                                 generateNonce() |
|    |                                                    nonce<= |    |
|    |                                                            |    |
|    |<----------------- subscribe(nonce, TpmName, ?PcrSelection) |    |
|    | {nonce} -------------------------------------------------->|    |
|    |                                                            |    |
| ===============[Evidence Generation and Conveyance]================= |
|    |                                                            |    |
| generateClaims(attestingEnvironment)                            |    |
|    | => PcrQuotes, eventLogs                                    |    |
|    |                                                            |    |
| collectClaims(PcrQuotes, ?PcrSelection)                         |    |
|    | => collectedClaims                                         |    |
|    |                                                            |    |
| generateEvidence(nonce, TpmName, collectedClaims)               |    |
|    | => evidence                                                |    |
|    |                                                            |    |
|    | {evidence, eventLogs} ------------------------------------>|    |
|    |                                                            |    |
| ========================[Evidence Appraisal]======================== |
|    |                                                            |    |
|    |                                      appraiseEvidence(evidence, |
|    |                                                      eventLogs, |
|    |                                                      verInputs) |
|    |                                       attestationResult <= |    |
|    ~                                                            ~    |
|    |                                                            |    |
| .--------[loop]----------------------------------------------------. |
||   |                                                            |   ||
|| ============[Delta Evidence Generation and Conveyance]============ ||
||   |                                                            |   ||
|| generateClaims(attestingEnvironment)                           |   ||
||   | => PcrQuotes, eventLogsDelta                               |   ||
||   |                                                            |   ||
|| collectClaims(PcrQuotes, ?PcrSelection)                        |   ||
||   | => collectedClaimsDelta                                    |   ||
||   |                                                            |   ||
|| generateEvidence(nonce, TpmName, collectedClaimsDelta)         |   ||
||   | => evidence                                                |   ||
||   |                                                            |   ||
||   | {evidence, eventLogsDelta} ------------------------------->|   ||
||   |                                                            |   ||
|| ====================[Delta Evidence Appraisal]==================== ||
||   |                                                            |   ||
||   |                                     appraiseEvidence(evidence, ||
||   |                                                eventLogsDelta, ||
||   |                                                     verInputs) ||
||   |                                       attestationResult <= |   ||
||   |                                                            |   ||
| '------------------------------------------------------------------' |
 '--------------------------------------------------------------------'
     |                                                            |
~~~~
{: #term-sequence title="YANG Subscription Model for Remote Attestation"}

### Time Considerations Mapping

{{-rats-arch}} defines "Relevant Events over Time" in RATS which also provides the input for Figure 3 of {{-rats-riv}}.
The following sequence diagram focusses on matching the defined events with the interactions between the Attester and the Verifying Relying Party.
The action of conveying "collectClaims", which is defined in {{Section 6 of -rats-models}}, is not defined by {{-rats-arch}}.
As a result, that action cannot be matched to a specified event time.

~~~~ aasvg
.----------.                             .--------------------------.
| Attester |                             | Verifier / Relying Party |
'----+-----'                             '---------------------+----'
   time(VG)                                                    |
generateClaims(attestingEnvironment)                           |
     | => PcrQuotes, eventLogs                                 |
     |                                                         |
     |<---------establish-subscription(<attestation>)------time(NS)
     |                                                         |
collectClaims(PcrQuotes, ?PcrSelection)                        |
     | => collectedClaims                                      |
     |                                                         |
   time(EG)                                                    |
generateEvidence(nonce, PcrSelection, collectedClaims)         |
     | => SignedPcrEvidence(nonce, PcrSelection)               |
     | => LogEvidence(collectedClaims)                         |
     |                                                         |
     |--filter(<pcr-extend>)---------------------------------->|
     |--<tpm12-attestation> or <tpm20-attestation>------------>|
     |--<log-retrieval>--------------------------------------->|
     |                                                         |
     |                                                  time(RG,RA)
     |                                  appraiseEvidence(evidence,
     |                                                  eventLogs,
     |                                                  verInputs)
     |                                    attestationResult <= |
     ~                                                         ~
   time(VG')                                                   |
generateClaims(attestingEnvironment)                           |
     | => PcrQuotes, eventLogsDelta                            |
     |                                                         |
collectClaims(PcrQuotes, ?PcrSelection)                        |
     | => collectedClaimsDelta                                 |
     |                                                         |
   time(EG')                                                   |
generateEvidence(nonce, TpmName, collectedClaimsDelta)         |
     | => evidence                                             |
     |                                                         |
     |--filter(<pcr-extend>)---------------------------------->|
     |--<tpm12-attestation> or <tpm20-attestation>------------>|
     |--<log-retrieval>--------------------------------------->|
     |                                                         |
     |                                                  time(RG,RA)
     |                                  appraiseEvidence(evidence,
     |                                                  eventLogs,
     |                                                  verInputs)
     |                                    attestationResult <= |
     |                                                         |
~~~~
{: #time-sequence title="YANG Subscription Model for Remote Attestation"}

* time(VG,RG,RA) are identical to the corresponding time definitions from {{-rats-riv}}.

* time(VG',RG',RA') are subsequent instances of the corresponding times from Figure 3 in {{-rats-riv}}.

* time(NS) – the subscriber generates a nonce and makes an {{RFC8639}} \<establish-subscription\> request based on that nonce value. This request also includes the augmentations defined in this document's YANG model. Key subscription RPC parameters include:
  * the nonce,
  * a set of PCRs of interest which the Verifier wants to be appraised, and
  * an optional filter that can reduce the logged events on the \<attestation\> stream pushed to the Verifier.

* time(EG) – an initial response of Evidence is returned to the Verifier. This includes:
  * a replay of filtered log entries, which have extended into a PCR of interest since boot, are sent in the \<pcr-extend\> notification, and
  * a signed TPM quote that contains at least the PCRs from the \<establish-subscription\> RPC are included in a \<tpm12-attestation\> or \<tpm20-attestation\>). This quote must have been generated based on the nonce value provided at time(NS).

* time(VG',EG') – this occurs when a PCR is extended subsequent to time(EG). Immediately after the extension, the following information needs to be pushed to the Verifier:
  * any values extended into a PCR of interest,
  * a signed TPM Quote showing the result the PCR extension, and
  * a nonce value (see 'handle' above or {{Section 6 of -rats-models}}), which is either the initially received nonce or a more recently received nonce value, for example, a nonce value extracted or derived from an Epoch ID (see {{Section 10.3 of -rats-arch}}) that contains a new nonce value or equivalent qualified data used as a nonce value.

One way to acquire a new time synchronisation that allows for the reuse of the initially received nonce as a fresh handle is elaborated on in {{freshness-handles}} below.

{: #freshness-handles "Continuously Verifying Freshness"}
## Continuously Verifying Freshness

As there is no new Verifier nonce provided at time(EG'), it is important to validate the freshness of TPM Quotes which are delivered at that time.  Methods of doing this verification vary based on the capabilities of the TPM cryptoprocessor used (see .

### TPM 1.2 Quote

The {{RFC8639}} notification format includes the \<eventTime\> object.  This can be used to determine the amount of time after the initial subscription each notification was sent.  However, this time is not returned as part of the signed results of the TPM Quote and therefore is not as trustworthy as the objects included in the TPM Quote.  Therefore, a Verifier MUST periodically issue a new nonce and receive this nonce within a TPM quote response in order to ensure the freshness of the results.  This can be done using the \<tpm12-challenge-response-attestation\> RPC from {{-charra}}.

### TPM 2 Quote

When the Attester includes a TPM2-compliant cryptoprocessor, internal time-related counters are included within the signed TPM Quote and thereby are trustworthy.  By including an initial nonce in the {{RFC8639}} subscription request, fresh values for these counters are pushed to the Verifier as part of the first TPM Quote.  In order to assess the freshness of the TPM Quotes that the Attester continuesly generates over time, the Verifier can aquire separate TPM Quotes via the \<tpm12-challenge-response-attestation\> RPC from {{-charra}} out-of-band.  These separate TPM Quotes include fresh time-related counters that can be appraised for freshness based on the predictable incrementing of these time-related counters. An example for how that can be realized is illustared in {{-TUDA}}.

The relevant internal time-related counters defined within {{TPM2.0}} can be seen within \<tpms-clock-info\>.   These counters include the \<clock\>, \<reset-counter\>, and \<restart-counter\> objects.  The rules for appraising these objects are as follows:

* If the \<clock\> has incremented for no more than the same duration as both the \<eventTime\> and the Verifier's internal time since the initial time(EG) and any previous time(EG'), then the TPM Quote is considered fresh. Note that {{TPM2.0}} allows for +/- 15% clock drift.  However, many hardware implementations significantly improve on this maximum drift.  If available, chip specific maximum drifts MUST be considered during the appraisal procedure of the Verifier.

* If the \<reset-counter\>, \<restart-counter\> has incremented, the existing subscription MUST be terminated, and a new \<establish-subscription\> SHOULD be generated.

* If a TPM Quote on any subscribed PCR has not been pushed to the Verifier for a duration of an Attester defined heartbeat interval, then a new TPM Quote notification SHOULD be sent to the Verifier.  This may often be the case, as certain PCRs might be infrequently updated.

~~~~ aasvg
.----------.                        .--------------------------.
| Attester |                        | Relying Party / Verifier |
'----------'                        '--------------------------'
   time(VG',EG')                                         |
     |-<tpm20-attestation>------------------------------>|
     |                                    :              |
     ~                           Heartbeat interval      ~
     |                                    :              |
   time(EG')                              :              |
     |-<tpm20-attestation>------------------------------>|
     |                                                   |
~~~~

{: #attestationstream}
# Remote Attestation Event Stream

The \<attestation\> Event Stream is an {{RFC8639}} compliant Event Stream which is defined within this section and within the YANG Module of {{-charra}}. This Event Stream contains YANG notifications which carry Evidence to assists a Verifier in appraising the Trustworthiness Level of an Attester. Data Nodes within {{configuring}} allow the configuration of this Event Stream's contents on an Attester.

This \<attestation\> Event Stream can only be exposed on Attesters supporting {{-rats-riv}}. As with {{-rats-riv}}, it is up to the Verifier to understand which types of cryptoprocessors and keys are acceptable.

## Subscription to the \<attestation\> Event Stream

To establish a subscription to an Attester in a way which provides provably fresh Evidence, initial randomness must be provided to the Attester. This is done via the augmentation of a \<nonce-value\> into {{RFC8639}} the \<establish-subscription\> RPC. Additionally, a Verifier must ask for PCRs of interest from a platform.

~~~~
  augment /sn:establish-subscription/sn:input:
    +---w nonce-value    binary
    +---w pcr-index*     tpm:pcr
~~~~

The result of the subscription will be that passing of the following information:

1. \<tpm12-attestation\> and \<tpm20-attestation\> notifications which include the provided \<nonce-value\>.  These attestation notifications MUST at least include all the PCRs identified by the pcr-index leaf-list requested in the RPC.

2. a series of \<pcr-extend\> notifications which reference the requested PCRs on all TPM based cryptoprocessors on the Attester.

3. \<tpm12-attestation\> and \<tpm20-attestation\> notifications generated within a few seconds of the \<pcr-extend\> notifications.  These attestation notifications MUST at least include any PCRs extended.

If the Verifier does not want to see the logged extend operations for all PCRs available from an Attester, an Event Stream Filter should be applied.  This filter will remove Evidence from any PCRs which are not interesting to the Verifier.

## Replaying a History of Previous TPM Extend Operations

Unless it is relying on Reference Values for TPM Quotes only, a Verifier will need to acquire a history of PCR extensions since the Attester has been booted.  This history may be requested from the Attester as part of the \<establish-subscription\> RPC.  This request is accomplished by placing a very old \<replay-start-time\> within the original RPC request.  As the very old \<replay-start-time\> will pre-date the time of Attester boot, a \<replay-start-time-revision\> will be returned in the \<establish-subscription\> RPC response, indicating when the Attester booted.  Immediately following the response (and before the notifications above) one or more \<pcr-extend\> notifications which document all extend operations which have occurred for the requested PCRs since boot will be sent.  Multiple extend operations to a single PCR index on a single TPM can be included within a single notification.

Note that if a Verifier has a partial history of extensions, the \<replay-start-time\> can be adjusted so that already known extensions are not forwarded.

The end of this history replay will be indicated with the {{RFC8639}} \<replay-completed\> notification.  For more on this sequence, see Section 2.4.2.1 of {{RFC8639}}.

After the \<replay-complete\> notification is provided, a TPM Quote will be requested and the result passed to the Verifier via a \<tpm12-attestation\> and \<tpm20-attestation\> notification.  If there have been any additional extend operations which have changed a subscribed PCR value in this quote, these MUST be pushed to the Verifier before the \<tpm12-attestation\> and \<tpm20-attestation\> notification.

At this point, the Verifier has sufficient Evidence to appraise the reported extend operations for each PCR, as well as to compare a Reference Value derived from the replay of the Event Log history of extensions of the PCR value against those extensions signed by the TPM in its most recent Quote.

### TPM2 Heartbeat

For TPM 2.0, every requested PCR MUST be sent within an \<tpm20-attestation\> and no less frequent than once per heartbeat interval.   This MAY be done with a single \<tpm20-attestation\> notification that includes all requested PCRs inside every heartbeat interval.  This MAY be done with several \<tpm20-attestation\> notifications at different times during a heartbeat interval.

## YANG Notifications Placed on the \<attestation\> Event Stream

### pcr-extend

This notification type documents when a subscribed PCR is extended within a single TPM cryptoprocessor.  It SHOULD be emitted no less than the \<marshalling-period\> after the PCR is first extended.  (The reason for the marshalling is that it is quite possible that multiple extensions to the same PCR have been made in quick succession, and these should be reflected in the same notification.)  This notification MUST be emitted prior to a \<tpm12-attestation\> or \<tpm20-attestation\> notification which has included and signed the results of any specific PCR extension.  If PCR extending events occur during the generation of the \<tpm12-attestation\> or \<tpm20-attestation\> notification, the marshalling period MUST be extended so that a new \<pcr-extend\> is not sent until the corresponding notifications have been sent.

~~~~
{::include ietf-tpm-remote-attestation-stream_pcr-extend.tree}
~~~~

Each \<pcr-extend\> MUST include one or more values being extended into the PCR.  These are passed within the \<extended-with\> object.  For each extension, details of the event SHOULD be provided within the \<event-details\> object.
The format of any included \<event-details\> is identified by the \<event-type\>.  This document includes two YANG structures which may be inserted into the \<event-details\>.  These two structures are: \<ima-event-log\> and \<bios-event-log\>.  Implementations wanting to provide additional documentation of a type of PCR extension may choose to define additional YANG structures which can be placed into \<event-details\>.

### tpm12-attestation

This notification contains an instance of a TPM1.2 style signed cryptoprocessor measurement. It is supplemented by Attester information which is not signed. This notification is generated and emitted from an Attester when at least one PCR identified within the subscribed \<pcr-indices\> has changed from the previous \<tpm12-attestation\> notification.  This notification MUST NOT include the results of any PCR extensions not previously reported by a \<pcr-extend\>.  This notification SHOULD be emitted as soon as a TPM Quote can extract the latest PCR hashed values.  This notification MUST be emitted prior to a subsequent \<pcr-extend\>.

~~~~
{::include ietf-tpm-remote-attestation-stream_tpm12-attestation.tree}
~~~~

All YANG objects above are defined within {{-charra}}.  The \<tpm12-attestation\> is not replayable.

### tpm20-attestation

This notification contains an instance of TPM2 style signed cryptoprocessor measurements. It is supplemented by Attester information which is not signed. This notification is generated at two points in time:

* every time at least one PCR has changed from a previous \<tpm20-attestation\>. In this case, the notification SHOULD be emitted promptly after the corresponding <pcr-extend> is sent, and no later than twice the configured marshalling-period. The marshalling-period value in effect is retrievable from /tpm:rats-support-structures.

* after a locally configurable minimum heartbeat period since a previous \<tpm20-attestation\> was sent.

~~~~
{::include ietf-tpm-remote-attestation-stream_tpm20-attestation.tree}
~~~~

All YANG objects above are defined within {{-charra}}.  The \<tpm20-attestation\> is not replayable.

## Filtering Evidence at the Attester

It can be useful *not* to receive all Evidence related to a PCR.  An example of this is when a Verifier maintains Reference Values (known good values) of a PCR.  In this case, it is not necessary to send a log of each consecutive extend operation.

To accomplish this reduction, when an RFC8639 \<establish-subscription\> RPC is sent, a \<stream-filter\> as per RFC8639, Section 2.2 can be set to discard a \<pcr-extend\>  notification when the \<pcr-index-changed\> is uninteresting to the verifier.

## Replaying Previous PCR Extend Events

To verify the value of a PCR, a Verifier must either know that the value is a "known good" value (see Section 2.3.3 of {{KGV}} about Reference Values) or be able to reconstruct the hash value by viewing all the PCR-Extends since the Attester rebooted. Wherever a hash reconstruction might be needed, the \<attestation\> Event Stream MUST support the RFC8639 \<replay\> feature. Through the \<replay\> feature, it is possible for a Verifier to retrieve and sequentially hash all of the PCR extending events since an Attester booted. Thereby, the Verifier has access to all the Evidence needed to verify a PCR's current value.

{: #configuring "Configuring the Attestation Stream"}
## Configuring the \<attestation\> Event Stream

{{attestationconfig}} is tree diagram which exposes the operator configurable elements of the \<attestation\> Event Stream. This allows an Attester to select what information should be available on the stream. A fetch operation also allows an external device such as a Verifier to understand the current configuration of the stream.

Almost all YANG objects below are defined via reference from {{-charra}}. However, there is one object which is new in this model. \<tpm2-heartbeat\> defines the maximum amount of time which should pass before a subscriber to the Event Stream should get a \<tpm20-attestation\> notification from devices which contain a TPM2.

~~~~
{::include ietf-tpm-remote-attestation-stream_attestation-config.tree}
~~~~
{: #attestationconfig title="Configuring the \<attestation\> Event Stream"}

{: #YANG-Module}
# YANG Module

This YANG module imports modules from {{-charra}} and {{RFC8639}}.

~~~~ YANG
<CODE BEGINS> ietf-tpm-remote-attestation-stream@2026-06-16.yang
{::include ietf-tpm-remote-attestation-stream@2026-06-16.yang}
<CODE ENDS>
~~~~

{: #otherstreams}
# Event Streams for Conceptual Messages

Analogous to the {{RFC8639}} compliant \<attestation\> Event Stream for the conveyance of remote attestation Evidence as defined in {{attestationstream}}, additional Event Streams can be defined for this YANG augment. Additional Event Streams for RATS Conceptual Messages MAY be conveyed either by subscribing to other YANG modules or by defining Event Streams for non-YANG-modeled data. In either case, any such additional Event Stream that extends this specification MUST be defined via a YANG augment to this module, ensuring consistent subscription and freshness semantics.

# Privacy Considerations

The privacy considerations of {{-rats-riv}} (Remote Integrity Verification of Network Devices Containing Trusted Platform Modules) apply.
Additionally, the security considerations from {{RFC8641}} (Subscription to YANG Notifications for Datastore Updates) how information about the system's internal structures or capabilities can be leaked, which could impact personally identifiable information (PII), apply.

There are no additional privacy considerations introduced by this document.

# Security Considerations

## Remote ATttestation procedureS (RATS)

The security considerations of {{-charra}} and {{-rats-riv}} apply.

## Yet Another Next Generation (YANG)

The YANG module defined in this document is designed to be accessed via network management protocols such as NETCONF {{RFC6241}} or RESTCONF {{RFC8040}}. The lowest NETCONF layer is the secure transport layer, and the mandatory-to-implement secure transport is SSH {{RFC6242}}; the lowest RESTCONF layer is HTTPS, with the mandatory-to-implement secure transport being TLS {{RFC8446}}. The Network Configuration Access Control Model (NACM) {{RFC8341}} provides the means to restrict access for particular users to a preconfigured subset of available protocol operations and content.

The security considerations of {{RFC9683}} and {{RFC9684}} (the CHARRA YANG model from which this module imports its data nodes) apply in full. The security requirements ({{Section 4.2.5 of RFC7923}}) and security considerations ({{Section 5 of RFC7923}}) of "Requirements for Subscription to YANG Datastores" apply, as do the considerations of {{RFC8639}} and {{RFC8641}}, which describe how the act of subscribing and the contents of notifications can leak information about a system's internal structure and state.

## Writable Data Nodes

There are a number of data nodes defined in this YANG module that are writable/creatable/deletable (i.e., config true, which is the default). These data nodes may be considered sensitive or vulnerable in some network environments. Write operations (e.g., edit-config) and delete operations to these data nodes without proper protection or authentication can have a negative effect on network operations. These are the subtrees and data nodes and their sensitivity/vulnerability:

* `/tpm:rats-support-structures/tras:marshalling-period`: This leaf controls the maximum delay between a PCR being extended and the corresponding `<pcr-extend>` notification reaching a subscriber. An attacker who can write this node can degrade the timeliness of Evidence: setting an excessively large value widens the window during which a malicious PCR extension can occur without being promptly reported, undermining the freshness guarantees that are the central purpose of this specification. Because the bound on the `<tpm20-attestation>` emission delay is derived from this value, tampering here also relaxes the signed-quote timing. Write access MUST be restricted.

* `/tpm:rats-support-structures/tras:tpm20-subscription-heartbeat` (and the `heartbeat` grouping it uses): This leaf governs how often a fresh, signed quote is pushed in the absence of PCR changes. Setting it to an excessively large value suppresses the periodic "still trustworthy" confirmation, allowing a Verifier to operate on stale Evidence for longer than intended; an attacker could use this to mask the absence of liveness. Setting it to an excessively small value can be used as a denial-of-service vector against the Attester's cryptoprocessor and against subscribers. Write access MUST be restricted.

* `/tpm:rats-support-structures/tras:tpm12-subscribed-signature-scheme` and `/tpm:rats-support-structures/tras:tpm20-subscribed-signature-scheme`: These leafrefs select the signature scheme used to sign all Evidence placed on the `<attestation>` stream. This is the most security-critical writable node set in the module. An attacker able to write these nodes could steer the Attester toward the weakest scheme the platform happens to support, weakening the cryptographic binding of every quote subsequently produced and potentially enabling forgery or downgrade attacks against the entire attestation relationship. Implementations SHOULD reject the selection of deprecated or weak schemes, and write access MUST be tightly restricted.

* `/tpm:rats-support-structures/tpm:tpms/tras:subscription-aik`: This leaf binds the notifications on the `<attestation>` stream of a given TPM to a specific Attestation Identity Key certificate-name. An attacker who can rewrite this node could cause Evidence to be signed under, or associated with, a key other than the one a Verifier expects, breaking the trust binding between the reported Evidence and the cryptoprocessor identity. This can facilitate masquerade or misattribution of Evidence. Write access MUST be restricted, and a Verifier SHOULD independently confirm the AIK/certificate it expects rather than relying solely on the configured value.

* `/tpm:rats-support-structures/tpm:tpms/tras:subscribable` (the `tpm12-stream`/`tpm20-stream` cases, including `tpm12-hash-algo`, `tpm20-hash-algo`, `tpm12-pcr-index`, and `tpm20-pcr-index`): These nodes determine which PCRs and which hash algorithms are eligible to be subscribed on a given TPM. An attacker able to modify these nodes can (a) remove security-relevant PCRs from the subscribable set, so that compromise reflected in those PCRs can never be streamed to a Verifier (a blinding attack), or (b) force a weak hash algorithm, undermining the integrity of the reported measurements. Write access MUST be restricted; removal of a PCR from the subscribable set is itself a security-relevant operation and SHOULD be auditable.

## Readable Data Nodes and Notifications

Some of the readable data nodes and, in particular, the notifications defined in this YANG module may be considered sensitive or vulnerable in some network environments. It is thus important to control read access (e.g., via get, get-config, or subscription) to these objects. These are the subtrees and data nodes and their sensitivity/vulnerability:

* The `<pcr-extend>`, `<tpm12-attestation>`, and `<tpm20-attestation>` notifications: These notifications carry remote attestation Evidence: signed TPM quotes, PCR index/value pairs, and detailed event-log entries (BIOS/UEFI, IMA, and network-equipment-boot logs via the `event-details` choice). Collectively this Evidence reveals the software and firmware composition, boot history, and configuration state of the Attester. Exposure to an unauthorized party provides a detailed map of the platform that is highly valuable for reconnaissance and targeted attack. The `<eventTime>` and `<up-time>` values, and the time-related counters carried within the TPM2 quote, additionally expose liveness and timing information. Read/subscribe access to the `<attestation>` Event Stream MUST be restricted to authorized Verifiers, and the transport MUST provide confidentiality.

* The configuration nodes in {{configuring-the-attestation-event-stream}} when read: The subscribable PCR set, configured signature scheme, heartbeat, marshalling period, and `subscription-aik` together describe the attestation posture and capabilities of the device. Disclosure aids an attacker in understanding what is and is not being monitored. Read access SHOULD be restricted consistent with the write protections above.

The nonce material conveyed at subscription time (the augmented `nonce-value`) and within quotes is freshness material, not a long-term secret; however, the binding between a nonce and the resulting quote MUST be protected in transit so that an on-path attacker cannot substitute or replay quotes.

## RPC Operations

This module augments the `establish-subscription` RPC defined in {{RFC8639}} with a `nonce-value` and a `pcr-index` selection. The security considerations for `establish-subscription` in {{RFC8639}} apply. Additionally:

* An attacker able to invoke this augmented RPC could establish unauthorized subscriptions to a TPM's Evidence (an information-disclosure vector equivalent to reading the notifications above), or could attempt resource exhaustion by establishing many subscriptions, requesting large replay histories (via a very old `<replay-start-time>`), or selecting large PCR sets. Implementations MUST authenticate and authorize subscribers and SHOULD apply rate limiting and per-subscriber resource bounds.

* The `nonce-value` is supplied by the subscriber. An Attester MUST treat it only as opaque freshness input to the quote and MUST NOT assume it carries any authorization meaning. A Verifier remains responsible for enforcing its own freshness policy on the returned quotes, since within a subscription a nonce may be reused subject to local policy.

## Privacy

See {{privacy-considerations}}. As noted there, the disclosure characteristics described in {{RFC8641}} regarding system internal structure also have privacy implications and apply to this module.

## Other

There are no additional security considerations introduced by this document.

# IANA Considerations {#IANA}

This document registers the following namespace URIs in the
{{xml-registry}} as per {{RFC3688}}:

URI:
: urn:ietf:params:xml:ns:yang:ietf-tpm-remote-attestation-stream

  Registrant Contact:
  : The IESG.

  XML:
  : N/A; the requested URI is an XML namespace.

This document registers the following YANG module in the
registry {{yang-parameters}} as per Section 14 of {{RFC6020}}:

Name:
: ietf-tpm-remote-attestation-stream

  Namespace:
  : urn:ietf:params:xml:ns:yang:ietf-tpm-remote-attestation-stream

  Prefix:
  : tras

  Reference:
  : draft-ietf-rats-network-device-subscription (RFC form)

--- back

# Acknowledgements
{: numbered="no"}

Shout-out to Thomas Fossati, Zhuoyao Lin, Yogesh Deshpande, Jun Zhang, Thanassis Giannetsos, Michael Richardson, Ned Smith, and Chunchi (Peter) Liu for their extensive review feedback that was vital to produce this document.
