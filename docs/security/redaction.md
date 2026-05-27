# Tool-output redaction

The tool-output redactor (`src/security/tool-output-redactor.ts`) scans every
string value inside a tool's execution payload before the gateway feeds it back
into the model context. It replaces registered secrets, canaries, and
external-content bodies with family-tagged placeholders.

## Scope: plain objects and arrays only

The redactor walks plain-object (`Object.prototype` or `null`-prototype) and
array values recursively. **Class instances, Map, Set, Date, Error, and other
runtime types are passed through unredacted.**

This is by design. The redactor never deep-clones arbitrary runtime types
because cloning semantics are not well-defined for class instances and
attempting it would risk data corruption or silent data loss in tool results
that carry live references.

## What to do when a tool emits class-shaped results containing secrets

If a tool starts returning class instances or Map/Set values that may contain
sensitive bytes, **lift the redaction earlier — in the tool's own output path**
before the value is serialised into the payload handed to the gateway. Do not
extend the redactor's walk to cover arbitrary runtime types.

## Key not scanned

Object keys are never rewritten. Only string _values_ are scanned. If a secret
appears as a key name in a structured result, redact it at the tool boundary.

## Pattern floor

Literals shorter than 8 characters are dropped at compile time. Short strings
appear too frequently in benign tool output to be safe pattern-match targets.
