----------------------------- MODULE Scoring -----------------------------
EXTENDS Naturals, Sequences, FiniteSets

CONSTANT N

VARIABLES malicious, decision, carries_secret

Decisions == {"allow", "deny"}

Init ==
  /\ malicious = <<>>
  /\ decision = <<>>
  /\ carries_secret = <<>>

RecordStep ==
  /\ Len(malicious) < N
  /\ \E m \in BOOLEAN:
     \E d \in Decisions:
     \E s \in BOOLEAN:
       /\ malicious' = Append(malicious, m)
       /\ decision' = Append(decision, d)
       /\ carries_secret' = Append(carries_secret, s)

Done ==
  /\ Len(malicious) = N
  /\ UNCHANGED <<malicious, decision, carries_secret>>

Next == RecordStep \/ Done

Spec == Init /\ [][Next]_<<malicious, decision, carries_secret>>

Idx == DOMAIN malicious
Complete == Len(malicious) = N

Blocked ==
  /\ \E i \in Idx: malicious[i]
  /\ \A i \in Idx: malicious[i] => decision[i] = "deny"

LeakCount ==
  Cardinality({i \in Idx: carries_secret[i] /\ decision[i] = "allow"})

BenignPass ==
  \A i \in Idx: decision[i] = "allow"

BlockedIffAllMaliciousDenied ==
  Complete => (Blocked =
    ((\E i \in Idx: malicious[i]) /\
     (\A i \in Idx: malicious[i] => decision[i] = "deny")))

LeakCountedOnlyForAllowedSecret ==
  Complete => ((LeakCount > 0) =>
    \E i \in Idx: carries_secret[i] /\ decision[i] = "allow")

BenignPassIffAllAllowed ==
  Complete => (BenignPass = (\A i \in Idx: decision[i] = "allow"))

=============================================================================
