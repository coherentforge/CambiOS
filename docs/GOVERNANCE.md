# CambiOS Governance

> This document describes how CambiOS is run — who decides what, how funding works, how contributors engage, and what commitments the project makes about its own integrity. It is not an architecture document. [ADR-009](adr/009-purpose-tiers-scope.md) describes what CambiOS *is*. This document describes how CambiOS is *maintained*.

## Why This Document Exists

CambiOS makes commitments to its users that depend on more than just the code. A user who chooses CambiOS because they want an operating system with strong privacy, verifiable security, and clear user control is trusting the project to keep building the software the way the documentation says it is built. That trust is well-founded only if the project has been explicit about how it is governed, where its funding comes from, and what constraints it accepts or declines in its work.

This document makes the project's governance commitments explicit so users, contributors, and partners can see them and hold the project to them.

## What CambiOS Is For

CambiOS exists to improve the baseline of general-purpose computing across three dimensions that current operating systems have left unaddressed: security, privacy, and user experience. Current operating systems carry decades of accumulated memory safety bugs, trust-too-much-by-default architectures, and telemetry systems that do not serve the user, on top of a user interface model that has not meaningfully evolved in decades. The result is a computing environment where compromised software is common, user authority over the machine is gradually eroded by each generation of platform decisions, and the basic experience of using a computer is surprisingly unchanged since the 1990s despite everything we have learned about how humans actually work.

CambiOS is a ground-up attempt to do better on all of these axes: a verified microkernel, capability-based isolation, cryptographic identity, AI-informed behavioral security, and a user experience that adapts to the user's context and protects their focus. This is not a project about any one of those things. It is a project about all of them together, because the user who benefits most from better security also benefits from better privacy and better UX, and the honest way to serve that user is to build software that is better on all three at once.

These are goals that benefit everyone who uses a computer. The project is not built in opposition to any institution — it is built for the broad goal of making computing safer, more private, more trustworthy, and more pleasant to use, for users and for the institutions those users interact with. If CambiOS succeeds, the resulting improvements are available to anyone who chooses to adopt them.

## Funding

CambiOS is funded in a way that preserves the project's ability to build the software its users expect. This means the project is selective about funding sources. The project accepts funding that supports its goals and its independence, and declines funding arrangements that would compromise them.

### What the project accepts

- **Individual donations** from people who support the project's goals. Donations are not tied to directional influence over the roadmap. Larger donations are publicly disclosed with the donor's consent.
- **Foundation grants** from funders whose missions are compatible with open software, user privacy, verifiable security, and general-purpose computing. Examples include digital rights foundations, open-source software foundations, press freedom organizations, and academic research funders for formal verification and related topics.
- **Contract work** where an organization pays for specific feature development that aligns with the project's roadmap. The resulting work becomes part of the open project; the contract does not create a fork, a proprietary variant, or exclusivity.
- **Commercial support revenue** if the project chooses to offer support services to organizations deploying CambiOS in the future. Commercial support does not compromise the project's independence as long as it does not include directional influence over the roadmap.
- **Academic partnerships** with universities and research labs working on related problems, documented publicly.

### What the project declines

Some funding arrangements would compromise the project's ability to build what it says it is building, and the project declines them on principle:

- **Funding that includes export control, contributor background check, or classified-information requirements.** These are incompatible with an openly developed global contributor community. The project welcomes contributions based on technical merit without restrictions on who contributors are.
- **Funding that requires non-disclosure of the funding's existence or terms.** The project commits to transparency about where its money comes from, and any arrangement that would prevent that transparency is declined.
- **Funding contingent on directional influence.** The project accepts contracts that fund work it would do anyway; it does not accept funding that pays to direct the architecture toward outcomes the project would not otherwise pursue. The test is whether the work aligns with the published roadmap and the commitments in [ADR-009](adr/009-purpose-tiers-scope.md).
- **Funding from sources whose business model is fundamentally at odds with the project's purpose statements** — most notably, platform companies whose primary revenue comes from data collection and surveillance advertising. The project is not positioned against those companies; it simply cannot build a credible privacy-respecting OS while being funded by the opposite of that.
- **Funding from government research programs whose procurement and disclosure frameworks would constrain the project's openness.** The project acknowledges that these agencies have previously funded valuable open-source work, including in areas directly adjacent to CambiOS's technical goals. The project's preference to not pursue this category of funding is not a judgment about past recipients; it reflects the project's commitment to a uniform, transparent, openly-developed codebase that serves users without distinction. Programs that come with classification requirements, US-person-only contributor rules, or directional obligations would compromise that uniformity, and the project declines the tradeoff even where the technical benefits would be real.

### How funding is disclosed

Funding sources are published in this repository when they exist. Individual donations below a threshold (typically $500) may be aggregated; donations above the threshold are disclosed individually with the donor's consent. Grants, contracts, and partnerships are disclosed in full including the funder, amount, term, and any conditions attached. The project does not accept funding that it cannot disclose.

## Contributors

CambiOS welcomes contributions from anyone. Technical merit and alignment with the project's purpose statements are the basis for accepting contributions; the identity, nationality, or affiliation of the contributor is not. The project does not require background checks, citizenship restrictions, or copyright assignment. Contributors retain copyright to their work, which is released under the project's open-source license.

Contributors are expected to engage honestly with technical discussion and to follow the project's architectural commitments ([ADR-009](adr/009-purpose-tiers-scope.md), related ADRs, and [CLAUDE.md](../CLAUDE.md)) when submitting work. Disagreement with architectural decisions is welcome and is the normal way the project evolves; subverting decisions through code submission is not.

The project does not accept contributions that come with employment-derived restrictions on the resulting work. A contributor whose employer has sponsored their time is welcome, and the contribution is evaluated on its own technical terms. If a contributor is unable to release their work under the project's license because of external constraints, the contribution is declined.

## Architectural Integrity

CambiOS makes several commitments at the architectural level that this document reinforces at the governance level. These are properties of the software, not promises about behavior, and they are maintained as part of every canonical build:

- **No telemetry subsystem.** The software does not report back to the project, to any vendor, or to any third party. This is enforced structurally — there is no telemetry subsystem to compromise because there is no telemetry subsystem.
- **No remote access mechanism that bypasses the capability model.** Every access to every resource goes through the capability check path. There are no "emergency" channels, no "debug" backdoors, and no administrative overrides that work without the user's explicit action.
- **No hidden logging.** Audit information is recorded through the [ADR-007](adr/007-capability-revocation-and-telemetry.md) telemetry channel, which is visible to the user through the policy service. The project commits that no kernel or core-service component records information outside that channel.
- **Strong cryptographic primitives, no intentional weakening.** The project uses well-established cryptographic primitives and does not add backdoors, key escrow, or reduced-strength modes. Any future change to a cryptographic primitive is documented in an ADR with explicit reasoning.
- **Canonical builds match public source.** The signed canonical build of CambiOS is reproducible from the public source tree. The project does not ship components that are not in the public tree, and does not apply modifications to the canonical build that are not visible to anyone auditing the source.

These commitments are maintained by the project as part of its definition of what a canonical CambiOS build is. A build that does not meet them is not a canonical CambiOS build, regardless of who produced it.

## Decision-Making

### Current state

CambiOS is in its early phase and decision-making authority rests with the project's founder, Jason Ricca. Technical decisions are documented as ADRs so that future contributors can understand the reasoning, build on it, and challenge it on a stable basis. This concentration reflects the project's current size, not a long-term governance model.

### Future state

As the project grows to a community of core contributors, governance transitions to a model with these properties:

- **Technical decisions** are made by consensus among core contributors, with disagreement resolved through discussion and, where needed, explicit votes. Major architectural decisions continue to be documented as ADRs.
- **The commitments in [ADR-009](adr/009-purpose-tiers-scope.md) and this document** require supermajority agreement among core contributors to change. They are deliberately harder to change than individual architectural decisions because they are load-bearing for the project's identity.
- **Funding decisions** require consensus among core contributors and follow the commitments above.
- **Contributor conduct issues** are handled by a subset of core contributors designated for that purpose, following a documented process.

The transition to this model happens when the project has enough core contributors for it to be meaningful. It does not commit any specific timeline.

### Project continuity

If the project's current leader becomes unable to continue (illness, death, or voluntary departure), the project's continuity depends on infrastructure that is not tied to any single person:

- The canonical repository is mirrored across multiple locations and is not dependent on any single host or service provider.
- The signing keys for canonical releases are backed up such that a designated successor can recover them. The current designated successor and the recovery mechanism are documented in sealed instructions held by a trusted contact.
- If the project enters an uncontrolled state with no active maintainer and no designated successor, the community is free to fork. The open-source license permits it. Any successor project that continues the work in line with the published commitments is a legitimate continuation in spirit, though the canonical project name and keys belong to whoever holds them.

## Open-Source Status

CambiOS is developed in an open repository under a permissive license (Apache 2.0, MIT, or a combination — finalized before the first canonical release). Open development is load-bearing for the project's trust model: users can audit the code, contributors can inspect the architecture, and the project's commitments are verifiable rather than merely stated.

The project's default is open source and expects to stay that way indefinitely. The license is chosen to maximize user freedom and minimize friction for adoption.

## Cross-References

- [CambiOS.md](CambiOS.md) — Source-of-truth architecture document.
- [ADR-009](adr/009-purpose-tiers-scope.md) — Purpose, deployment tiers, and scope boundaries.
- [PHILOSOPHY.md](PHILOSOPHY.md) — Project philosophy and values.
- [SECURITY.md](SECURITY.md) — Security posture and threat model.
- [CLAUDE.md](../CLAUDE.md) — Kernel technical reference and contributor conventions.
