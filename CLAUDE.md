# Writing style for this repository

All prose in this repository (documentation, library text that appears in reports, report
templates, and comments that explain a decision) follows the style below. It is drawn from the
maintainer's own analytical writing and adapted for technical documentation: the structure and
voice carry over, while the persuasive framing does not.

## What to keep

**Lead with the claim, then support it, then close it.** A paragraph opens with a topic sentence
that states its point plainly. The sentences after it give the evidence (the rule's gate, the
model's fields, a test result, a source), and the last sentence draws the conclusion, often
opening with "Thus," "Ultimately," "As a result," or "In the end."

**Signpost the structure.** A section that covers several items says so up front and then
walks through them in order: "This rule has three conditions. First, ... Second, ...
Third, ..." Ordinal phrasing ("The first condition relates to ...", "The second concerns
...") is preferred over bare fragments. A long section ends with a short wrap-up that ties the
items together.

**Define terms and criteria explicitly.** State exactly when something counts: "A finding
counts as a control verification when (1) the model shows the interface exists, and (2) nothing
in the model shows whether the control is in place." Inline numbered criteria, written as
(1), (2), (3), suit gates and classification rules. Say what a definition includes and what it
leaves out.

**Weigh both sides, then decide.** Where there is a trade-off, present it as "On one hand,
... On the other hand, ..." or "While X, Y," and then state the decision and the reason for
it. Do not leave a trade-off open without a conclusion.

**State limitations plainly.** After a conclusion, name its weak points in their own
paragraph, typically opening with "Having said that," or "However,". Say what the limitation
could change and what would resolve it.

**Calibrate certainty to the evidence.** Be definite when the evidence is definite ("The
results show", "This rule fires on"). Use "likely," "might," "appears to," or "suggests" only
where the evidence is genuinely mixed, and say why it is mixed.

**Use transitions at the start of sentences, followed by a comma.** The usual set is: However,
Additionally, Specifically, For example, For instance, For starters, Furthermore, Thus,
Therefore, Ultimately, Essentially, Nevertheless, Having said that, In the end, In other
words. "Namely" and "specifically" introduce the exact items after a general statement.

**Write medium-length sentences.** Aim for about 20 words, with a range from about 10 to 35,
and about four to six sentences per paragraph. Subordinate clauses often come first: "Though
the rule fires on every database, ...", "Because the gateway is in scope, ...", "While the
model shows the link, ...".

**Cite the source in parentheses.** Standards and evidence go in parentheses after the claim
they support, the way an academic citation would: "(CAPEC-115)", "(NIST SP 800-53 AC-6)",
"(ATT&CK T1190)", "(see 08-risk-tracking-lib.yml)".

**Allow a candid judgment.** When something is wrong, say so directly and concretely ("This
is noise," "This falls flat for an in-scope gateway"), then give the reason.

## What to leave out

- No persuasive framing: no "this paper argues," rhetorical questions, or literature-review
  chains. State findings and decisions directly.
- No contractions, exclamation marks, or semicolons. Split a semicolon sentence into two, or
  join the halves with "while," "whereas," or "and."
- No em dashes or " -- " asides. Use a comma, parentheses, or a new sentence. Use a colon to
  introduce a definition or a list.
- No first person in documentation. Refer to "this framework," "this rule," or "this
  document." First person is acceptable only in commit messages and review notes.
- No filler intensifiers ("crucial," "robust," "seamless," "leverage," "delve") and no
  bold-label lead-ins on every paragraph. Bold is for terms being defined.

## Code comments

Comments follow the same voice, but they are shorter than documentation. A comment explains
why the code does what it does, in its current form. Specifically:

- State the decision and the reason for it. Leave the history (what was tried, what was
  removed, what an older version did) to git and the commit messages.
- Keep a comment in proportion to the code it explains. One or two sentences usually
  suffice, and a block longer than about eight lines belongs in the documentation instead,
  with the comment pointing to it.
- Do not restate what the code plainly says.

## What not to rewrite

- Text quoted from a standard stays identical to the source. This covers the OWASP
  ASVS/AISVS requirement rows in the security requirements (the `number | text | level`
  rows), NIST control statements, and CAPEC or ATT&CK names.
- Identifiers and keys: category titles used as YAML keys, rule IDs, tag names, field names,
  and abuse-case and requirement titles (the report pairs them on their control IDs).
- The "As an attacker, I want to ..., so that ..." form of abuse cases. Its structure is
  fixed, while the wording inside it follows this guide.
- Upstream Threagile text that this project has not changed, legal notices, and licenses.
  Once this project changes a piece of upstream text, the changed text follows this guide.
