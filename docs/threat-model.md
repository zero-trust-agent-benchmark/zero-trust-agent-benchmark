# Threat Model

## Attacker capabilities

Attackers may place untrusted text in retrieved documents, tool outputs, MCP
tool descriptions, parser-facing model generations, destination URLs, and other
tool arguments. They may try prompt injection, control-token injection, tool
hijacking, tool poisoning, parser confusion, data exfiltration, and privilege
escalation.

## Defender goal

A defense decides each tool call independently from the request, agent identity
and posture, context, arguments, and prior decisions. It must deny malicious
steps while allowing benign workflows and preventing encoded secret exfiltration.

## Out of scope

Model training compromise, real credential theft, network exploitation, and
post-benchmark human review are out of scope for v0.1.0.
