# Writing style

All prose in this repository (documentation, user-facing text, report and template wording,
commit messages, and code comments) follows the style below. It is drawn from the
maintainer's own analytical writing and adapted for technical documentation: the structure and
voice carry over, while the persuasive framing does not.

## What to keep

**Lead with the claim, then support it, then close it.** A paragraph opens with a topic sentence
that states its point plainly. The sentences after it give the evidence (the code's behavior, a
configuration value, a test result, a measurement, a source), and the last sentence draws the
conclusion, often opening with "Thus," "Ultimately," "As a result," or "In the end."

**Signpost the structure.** A section that covers several items says so up front and then
walks through them in order: "This check has three conditions. First, ... Second, ...
Third, ..." Ordinal phrasing ("The first condition relates to ...", "The second concerns
...") is preferred over bare fragments. A long section ends with a short wrap-up that ties the
items together.

**Define terms and criteria explicitly.** State exactly when something counts: "A request
counts as authenticated when (1) it carries a valid token, and (2) the token's audience matches
this service." Inline numbered criteria, written as (1), (2), (3), suit conditions, gates and
classification rules. Say what a definition includes and what it leaves out.

**Weigh both sides, then decide.** Where there is a trade-off, present it as "On one hand,
... On the other hand, ..." or "While X, Y," and then state the decision and the reason for
it. Do not leave a trade-off open without a conclusion.

**State limitations plainly.** After a conclusion, name its weak points in their own
paragraph, typically opening with "Having said that," or "However,". Say what the limitation
could change and what would resolve it.

**Calibrate certainty to the evidence.** Be definite when the evidence is definite ("The
results show", "This function returns"). Use "likely," "might," "appears to," or "suggests"
only where the evidence is genuinely mixed, and say why it is mixed.

**Use transitions at the start of sentences, followed by a comma.** The usual set is: However,
Additionally, Specifically, For example, For instance, For starters, Furthermore, Thus,
Therefore, Ultimately, Essentially, Nevertheless, Having said that, In the end, In other
words. "Namely" and "specifically" introduce the exact items after a general statement.

**Write medium-length sentences.** Aim for about 20 words, with a range from about 10 to 35,
and about four to six sentences per paragraph. Subordinate clauses often come first: "Though
the job retries, ...", "Because the cache is shared, ...", "While the API accepts the field,
...".

**Cite the source in parentheses.** Standards, specifications and evidence go in parentheses
after the claim they support, the way an academic citation would: "(RFC 6749 section 4.1)",
"(NIST SP 800-53 AC-6)", "(see docs/architecture.md)".

**Allow a candid judgment.** When something is wrong, say so directly and concretely ("This
is noise," "This approach falls flat under load"), then give the reason.

## What to leave out

- No persuasive framing: no "this paper argues," rhetorical questions, or literature-review
  chains. State findings and decisions directly.
- No contractions, exclamation marks, or semicolons. Split a semicolon sentence into two, or
  join the halves with "while," "whereas," or "and."
- No em dashes or " -- " asides. Use a comma, parentheses, or a new sentence. Use a colon to
  introduce a definition or a list.
- No first person in documentation. Refer to "this project," "this module," or "this
  document." First person is acceptable only in commit messages and review notes.
- No filler intensifiers ("crucial," "robust," "seamless," "leverage," "delve") and no
  bold-label lead-ins on every paragraph. Bold is for terms being defined.

## Code comments

Comments follow the same voice, but they are shorter than documentation. A comment explains
why the code does what it does, in its current form. Specifically:

- State the decision and the reason for it. Leave the history (what was tried, what was
  removed, what an older version did) to version control and the commit messages.
- Keep a comment in proportion to the code it explains. One or two sentences usually
  suffice, and a block longer than about eight lines belongs in the documentation instead,
  with the comment pointing to it.
- Do not restate what the code plainly says.

## What not to rewrite

- Text quoted from a standard, specification, or other external source stays identical to the
  source. This covers requirement text, control statements, error messages from other tools,
  and quoted passages.
- Identifiers and keys: names that code, configuration, or tests match on, such as field
  names, map keys, IDs, enum values, and titles used as lookup keys.
- Fixed formats that other tools or readers depend on, such as user-story templates, log
  formats, and structured headers. The wording inside them follows this guide.
- Third-party text this project has not changed, legal notices, and licenses. Once this
  project changes a piece of third-party text, the changed text follows this guide.
