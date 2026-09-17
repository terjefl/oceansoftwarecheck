"""Rule engine: compares a parsed OLP report against requirements.yaml.

The requirements model follows the association's table from the 2026-08 web
meeting ("MINIMUM ECU requirements"): each relevant ECU has a minimum level per
software profile (2.0, 2.1, ...). A car is "100% <profile>" when ALL required
modules reach at least the profile's level. A 100% 2.1 car can be updated
directly to Marlin; a car with mixed levels (a "zebra") must first go via
SW 2.2 / targeted module updates.

The number being compared is extracted from the "Supplier SW Version" field
with a module-specific regex (`extract` in the YAML, capture group 1), because
the field's shape differs per supplier (BCM395021, MCU5000019, "ECC395 24",
89324V04...).

requirements.yaml is bind-mounted into the container and re-read on every
evaluation, so updated requirements take effect immediately without a rebuild.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .parser import ModuleReading, ParsedReport

# Module status
OK = "ok"                    # level >= target profile requirement
OUTDATED = "outdated"        # level < target profile requirement
MISSING = "missing"          # required module not found in the report
UNPARSEABLE = "unparseable"  # could not extract a number from Supplier SW Version
EMPTY = "empty"              # the Supplier SW Version field was blank in the report

VERDICT_READY = "ready"
VERDICT_ZEBRA = "zebra"
VERDICT_MARLIN = "marlin"    # the car already runs Marlin; the readiness check does not apply

# Outcomes: the association's finer classification (Sep 2026). `verdict` is
# derived from the outcome so older code keeps working.
#   marlin    already on Marlin (VCU 2.4)
#   full_22   every module at the highest profile: fully 2.2, Marlin-ready
#   full_21   every module at the target profile and NONE showing evidence of
#             the highest profile: a clean 2.1 car, Marlin-ready, but a direct
#             update leaves the 2.2-only ECUs behind (recommend 2.2 first)
#   zebra_22  every module at the target profile, some already at the highest
#             one: a started-but-incomplete 2.2 ("2.2 zebra"); Marlin-ready in
#             principle, but finish 2.2 first
#   zebra_21  at least one module below the target profile: not Marlin-ready
OUTCOME_MARLIN = "marlin"
OUTCOME_FULL_TOP = "full_22"
OUTCOME_FULL_TARGET = "full_21"
OUTCOME_ZEBRA_TOP = "zebra_22"
OUTCOME_ZEBRA_TARGET = "zebra_21"
OUTCOMES = [OUTCOME_FULL_TOP, OUTCOME_FULL_TARGET, OUTCOME_ZEBRA_TOP, OUTCOME_ZEBRA_TARGET, OUTCOME_MARLIN]

# Fallback when the module has no extract regex of its own: last digit group
_DEFAULT_EXTRACT = re.compile(r"(\d+)\s*$")


@dataclass
class Variant:
    """A trim/region-specific flavor of a module (e.g. BMS for LFP vs NMC packs,
    or RHD vs LHD steering). The first variant whose `pattern` matches the
    Supplier SW Version is used; its extract replaces the module's and its
    levels override the module's profile by profile (a profile the variant
    does not mention keeps the module's level)."""

    name: str
    pattern: str                  # regex matched against Supplier SW Version
    levels: dict[str, int]
    extract: str | None = None


@dataclass
class Requirement:
    id: str
    match: list[str]              # ECU codes in the report (e.g. ["MCU_R", "MCU_RR"])
    levels: dict[str, int]        # profile -> minimum level, e.g. {"2.0": 19, "2.1": 21}
    extract: str | None = None    # regex with a capture group, applied to Supplier SW Version
    critical: bool = True
    label: str = ""
    variants: list[Variant] = field(default_factory=list)
    # Level at which this module shows the car is ALREADY on Marlin (e.g. VCU
    # 24 = "VCU 2.4", which only Marlin installs). When every module that has
    # a marlin_level reaches it, the verdict is "marlin" instead of
    # ready/zebra. None = this module is not a Marlin marker.
    marlin_level: int | None = None
    # Trim letters (5th VIN character: Z/E/U/S = One/Extreme/Ultra/Sport) this
    # module is required for. None = required for all trims. Example: MCU_R is
    # absent on the single-motor Sport, so only_trims: [Z, E, U]. The exemption
    # only applies to a KNOWN trim letter: a VIN whose trim cannot be decoded
    # still requires every module (fail-safe, see `evaluate`).
    only_trims: list[str] | None = None


@dataclass
class MarlinRequirement:
    """A module that the Marlin update installs, and the level it installs.
    Only used to tell a car that is already on Marlin whether the whole
    Marlin package is in place; it never affects the outcome."""
    id: str
    match: list[str]
    marlin_level: int
    extract: str | None = None
    label: str = ""


@dataclass
class MarlinResult:
    requirement: MarlinRequirement
    version: str = ""             # Supplier SW Version as found, "" if the module is missing
    extracted: int | None = None
    ok: bool = False              # extracted >= marlin_level; doubt never gives ok
    status: str = MISSING         # ok / outdated / missing / unparseable / empty


@dataclass
class RequirementSet:
    version: str
    target_profile: str           # profile required for direct Marlin (currently "2.1")
    profiles: list[str]           # ascending order, e.g. ["2.0", "2.1"]
    modules: list[Requirement]
    notes: str = ""               # free text: sources and open points, kept by the admin form
    marlin_modules: list[MarlinRequirement] = field(default_factory=list)


@dataclass
class ModuleResult:
    requirement: Requirement
    status: str
    raw_name: str = ""
    version: str = ""             # Supplier SW Version as found in the report
    extracted: int | None = None  # the extracted number
    required: int | None = None   # the target profile minimum level
    level: str | None = None      # highest profile the module satisfies, None = below all
    variant: str = ""             # name of the matched variant, if any
    top_required: int | None = None  # minimum for the highest profile (variant-aware), if defined
    # Per profile: does the module meet that profile's minimum? None = the
    # profile defines no level for this module. A module without a number
    # (missing/empty/unparseable) meets nothing.
    meets: dict[str, bool | None] = field(default_factory=dict)
    # The LOWEST profile whose minimum equals the minimum of the highest
    # profile the module satisfies. Where two profiles share a minimum (BMS is
    # 21 on every profile, BCM 30 on 2.0 and 2.1) a reading cannot prove the
    # higher one, so it only counts as evidence of the lower. Drives the
    # "zebra" detection.
    evidence_level: str | None = None
    # variant-aware levels actually used for this module (profile -> minimum)
    levels: dict[str, int] = field(default_factory=dict)
    # the report line this result was computed from (None when missing)
    reading: ModuleReading | None = field(default=None, repr=False, compare=False)


@dataclass
class Evaluation:
    verdict: str
    requirements_version: str
    target_profile: str
    results: list[ModuleResult]
    profiles: list[str] = field(default_factory=list)
    extra_modules: list = field(default_factory=list)  # report modules without a requirement
    trim: str = ""                # trim letter read from the VIN (5th character)
    trim_name: str = ""           # "One"/"Extreme"/"Ultra"/"Sport", or "" if the letter is unknown
    outcome: str = ""             # one of OUTCOMES
    complete_profile: str | None = None  # highest profile every required module meets
    top_evidence: str | None = None      # highest evidence_level over the modules
    marlin_results: list[MarlinResult] = field(default_factory=list)  # the Marlin package, per module

    @property
    def marlin_below(self) -> list[MarlinResult]:
        """Modules the Marlin update installs that are not at the Marlin level."""
        return [r for r in self.marlin_results if not r.ok]

    @property
    def marlin_complete(self) -> bool:
        return bool(self.marlin_results) and not self.marlin_below

    @property
    def unread(self) -> list[ModuleResult]:
        """Required modules the report gave no usable version for (missing,
        empty or unrecognised): the result is based on an incomplete report."""
        return [r for r in self.results if r.status in (MISSING, EMPTY, UNPARSEABLE)]

    def below(self, profile: str) -> list[ModuleResult]:
        """Modules that do not meet `profile` (no number counts as below)."""
        return [r for r in self.results if r.meets.get(profile) is False]

    def meeting(self, profile: str) -> list[ModuleResult]:
        return [r for r in self.results if r.meets.get(profile) is True]

    @property
    def ok_below_top(self) -> list[ModuleResult]:
        """Modules that meet the target profile but not the highest profile —
        i.e. what a direct 2.1→Marlin update will leave behind (2.2-only ECUs).
        Only modules that actually DEFINE a level for the top profile can be
        below it; a module with no top-profile requirement is not listed."""
        return [
            r for r in self.results
            if r.status == OK
            and r.top_required is not None
            and r.extracted is not None
            and r.extracted < r.top_required
        ]

    @property
    def below_top(self) -> list[ModuleResult]:
        """Every module with a number that is below the highest profile,
        whatever its status. Used for cars already on Marlin, which does not
        update every ECU: this is what is still on older software."""
        return [
            r for r in self.results
            if r.top_required is not None
            and r.extracted is not None
            and r.extracted < r.top_required
        ]

    @property
    def failing(self) -> list[ModuleResult]:
        return [r for r in self.results if r.status != OK]

    @property
    def failing_critical(self) -> list[ModuleResult]:
        return [r for r in self.results if r.status != OK and r.requirement.critical]


class RequirementsValidationError(Exception):
    """The requirements text could not be parsed as a valid rule set."""


def parse_requirements_text(text: str) -> RequirementSet:
    """Parses and validates requirements text (YAML). Raises RequirementsValidationError."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RequirementsValidationError(f"Invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise RequirementsValidationError("The top level must be a YAML mapping.")
    try:
        result = _build_requirement_set(raw)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise RequirementsValidationError(f"Invalid structure: {exc!r}") from exc
    if not result.modules:
        raise RequirementsValidationError("No modules defined under `modules:`.")
    if not result.target_profile or result.target_profile == "None":
        raise RequirementsValidationError("`target_profile` is missing.")
    if result.target_profile not in result.profiles:
        raise RequirementsValidationError(
            f"target_profile {result.target_profile!r} is not in profiles {result.profiles}."
        )
    for module in result.modules:
        for owner, extract in [(module.id, module.extract)] + [
            (f"{module.id}/{v.name}", v.extract) for v in module.variants
        ]:
            if not extract:
                continue
            try:
                pattern = re.compile(extract)
            except re.error as exc:
                raise RequirementsValidationError(
                    f"Module {owner}: invalid extract regex: {exc}"
                ) from exc
            if pattern.groups < 1:
                raise RequirementsValidationError(
                    f"Module {owner}: the extract regex has no capture group."
                )
        for variant in module.variants:
            try:
                re.compile(variant.pattern)
            except re.error as exc:
                raise RequirementsValidationError(
                    f"Module {module.id}/{variant.name}: invalid pattern: {exc}"
                ) from exc
        has_base_target = module.levels.get(result.target_profile) is not None
        variants_cover_target = bool(module.variants) and all(
            v.levels.get(result.target_profile) is not None for v in module.variants
        )
        if not has_base_target and not variants_cover_target:
            raise RequirementsValidationError(
                f"Module {module.id}: missing level for target_profile {result.target_profile!r}"
                " (set it on the module or on every variant)."
            )
    return result


def load_requirements(path: str | Path) -> RequirementSet:
    return parse_requirements_text(Path(path).read_text(encoding="utf-8"))


def _str_list(value, where: str) -> list[str]:
    """A YAML list of scalars. A bare string is rejected: iterating over
    `match: VCU` would silently yield ["V", "C", "U"] and mark the module
    missing on every car."""
    if not isinstance(value, list) or not value:
        raise RequirementsValidationError(f"{where} must be a non-empty list (e.g. [VCU]).")
    if not all(isinstance(item, (str, int, float)) for item in value):
        raise RequirementsValidationError(f"{where} must contain only plain values.")
    return [str(item) for item in value]


def _levels(value, where: str) -> dict[str, int]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RequirementsValidationError(f"{where} must be a mapping of profile -> integer level.")
    out: dict[str, int] = {}
    for k, v in value.items():
        if isinstance(v, bool) or not isinstance(v, (int, float)) or int(v) != v:
            raise RequirementsValidationError(
                f"{where}: level for profile {k!r} must be an integer (got {v!r})."
            )
        out[str(k)] = int(v)
    return out


def _mapping(value, where: str) -> dict:
    if not isinstance(value, dict):
        raise RequirementsValidationError(f"{where} must be a mapping.")
    return value


def _optional_str(value, where: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RequirementsValidationError(f"{where} must be a string.")
    return value


def _build_requirement_set(raw: dict) -> RequirementSet:
    raw_modules = raw.get("modules", [])
    if not isinstance(raw_modules, list):
        raise RequirementsValidationError("`modules` must be a list.")
    modules = []
    for index, m in enumerate(raw_modules):
        m = _mapping(m, f"modules[{index}]")
        if "id" not in m or not isinstance(m["id"], str) or not m["id"].strip():
            raise RequirementsValidationError(f"modules[{index}]: `id` is missing or not a string.")
        module_id = m["id"].strip()
        where = f"Module {module_id}"
        raw_variants = m.get("variants", [])
        if raw_variants is None:
            raw_variants = []
        if not isinstance(raw_variants, list):
            raise RequirementsValidationError(f"{where}: `variants` must be a list.")
        variants = []
        for v_index, v in enumerate(raw_variants):
            v = _mapping(v, f"{where}: variants[{v_index}]")
            for key in ("name", "pattern"):
                if not isinstance(v.get(key), str) or not v[key]:
                    raise RequirementsValidationError(
                        f"{where}: variants[{v_index}] needs a string `{key}`."
                    )
            variants.append(
                Variant(
                    name=v["name"],
                    pattern=v["pattern"],
                    levels=_levels(v.get("levels"), f"{where}/{v['name']}: `levels`"),
                    extract=_optional_str(v.get("extract"), f"{where}/{v['name']}: `extract`"),
                )
            )
        marlin_level = m.get("marlin_level")
        if marlin_level is not None and (
            isinstance(marlin_level, bool) or not isinstance(marlin_level, int)
        ):
            raise RequirementsValidationError(f"{where}: `marlin_level` must be an integer.")
        modules.append(
            Requirement(
                id=module_id,
                marlin_level=marlin_level,
                match=[
                    code.upper()
                    for code in _str_list(m.get("match", [module_id]), f"{where}: `match`")
                ],
                levels=_levels(m.get("levels"), f"{where}: `levels`"),
                extract=_optional_str(m.get("extract"), f"{where}: `extract`"),
                critical=bool(m.get("critical", True)),
                label=str(m.get("label") or module_id),
                variants=variants,
                only_trims=(
                    [t.upper() for t in _str_list(m["only_trims"], f"{where}: `only_trims`")]
                    if m.get("only_trims")
                    else None
                ),
            )
        )
    notes = raw.get("notes", "")
    if notes is not None and not isinstance(notes, str):
        raise RequirementsValidationError("`notes` must be a string.")
    raw_marlin = raw.get("marlin_modules")
    if raw_marlin is None:
        raw_marlin = []
    if not isinstance(raw_marlin, list):
        raise RequirementsValidationError("`marlin_modules` must be a list.")
    marlin_modules = []
    for index, m in enumerate(raw_marlin):
        m = _mapping(m, f"marlin_modules[{index}]")
        if not isinstance(m.get("id"), str) or not m["id"].strip():
            raise RequirementsValidationError(f"marlin_modules[{index}]: `id` is missing or not a string.")
        where = f"Marlin module {m['id'].strip()}"
        level = m.get("marlin_level")
        if isinstance(level, bool) or not isinstance(level, int):
            raise RequirementsValidationError(f"{where}: `marlin_level` must be an integer.")
        extract = _optional_str(m.get("extract"), f"{where}: `extract`")
        if extract:
            try:
                if re.compile(extract).groups < 1:
                    raise RequirementsValidationError(f"{where}: the extract regex has no capture group.")
            except re.error as exc:
                raise RequirementsValidationError(f"{where}: invalid extract regex: {exc}") from exc
        marlin_modules.append(MarlinRequirement(
            id=m["id"].strip(),
            match=[c.upper() for c in _str_list(m.get("match", [m["id"]]), f"{where}: `match`")],
            marlin_level=level,
            extract=extract,
            label=str(m.get("label") or m["id"]).strip(),
        ))

    return RequirementSet(
        version=str(raw.get("version", "unknown")),
        target_profile=str(raw.get("target_profile")),
        profiles=_str_list(raw.get("profiles"), "`profiles`"),
        modules=modules,
        notes=notes or "",
        marlin_modules=marlin_modules,
    )


def _extract_number(supplier_sw: str, extract: str | None) -> int | None:
    pattern = re.compile(extract) if extract else _DEFAULT_EXTRACT
    m = pattern.search(supplier_sw)
    if not m:
        return None
    try:
        return int(m.group(1))
    except (IndexError, ValueError):
        return None


def _profile_level(extracted: int, levels: dict[str, int], profiles: list[str]) -> str | None:
    """Highest profile (in ascending order) whose requirement is satisfied."""
    level = None
    for profile in profiles:
        minimum = levels.get(profile)
        if minimum is not None and extracted >= minimum:
            level = profile
    return level


def _evidence_level(extracted: int, levels: dict[str, int], profiles: list[str]) -> str | None:
    """Lowest profile sharing the minimum of the highest satisfied profile."""
    satisfied = _profile_level(extracted, levels, profiles)
    if satisfied is None:
        return None
    minimum = levels[satisfied]
    for profile in profiles:
        if levels.get(profile) == minimum:
            return profile
    return satisfied


def _meets(extracted: int | None, levels: dict[str, int], profiles: list[str]) -> dict[str, bool | None]:
    out: dict[str, bool | None] = {}
    for profile in profiles:
        minimum = levels.get(profile)
        if minimum is None:
            out[profile] = None
        elif extracted is None:
            out[profile] = False
        else:
            out[profile] = extracted >= minimum
    return out


def incompleteness(report: ParsedReport, evaluation: Evaluation) -> str | None:
    """Why the report cannot be accepted as a complete OLP export, or None.
    Three structural checks: every section heading present, at least
    MIN_MODULES control units, and every required module present as a block
    (a present block with an empty or NA version is fine: that is an ECU that
    did not answer, which the outcome reports). Modules a trim does not have
    (MCU_R on the Sport) are not counted as missing, since the evaluation
    already leaves them out."""
    from .parser import MIN_MODULES, REQUIRED_SECTIONS

    sections = {m.section for m in report.modules}
    absent = [name for name in REQUIRED_SECTIONS if name not in sections]
    if absent:
        return "section " + ", ".join(absent) + " missing"
    if len(report.modules) < MIN_MODULES:
        return f"{len(report.modules)} control units, at least {MIN_MODULES} expected"
    missing = [r.requirement.id for r in evaluation.results if r.status == MISSING]
    if missing:
        return "module " + ", ".join(missing) + " missing"
    return None


TRIM_NAMES = {"Z": "One", "E": "Extreme", "U": "Ultra", "S": "Sport"}


def vin_trim(vin: str) -> str:
    """Trim letter from the VIN (5th character): Z/E/U/S = One/Extreme/Ultra/Sport."""
    return vin[4].upper() if len(vin) > 4 else ""


def evaluate(report: ParsedReport, requirements: RequirementSet) -> Evaluation:
    results: list[ModuleResult] = []
    matched: list[ModuleReading] = []  # the exact readings used, so duplicates stay visible
    target = requirements.target_profile
    trim = vin_trim(report.vin)
    trim_known = trim in TRIM_NAMES

    for req in requirements.modules:
        reading = next(
            (m for m in report.modules if m.code.upper() in req.match), None
        )
        if reading is None:
            # A module absent from the report is only a failure if this trim is
            # supposed to have it (e.g. the single-motor Sport has no MCU_R).
            # An unknown trim letter never exempts anything: treating it as
            # "not required" would let a two-motor car pass with MCU_R missing.
            if req.only_trims and trim_known and trim not in req.only_trims:
                continue
            results.append(
                ModuleResult(
                    requirement=req, status=MISSING, required=req.levels.get(target),
                    meets=_meets(None, req.levels, requirements.profiles), levels=dict(req.levels),
                )
            )
            continue
        matched.append(reading)

        # Variant selection: first variant whose pattern matches the value wins
        extract_regex = req.extract
        levels = req.levels
        variant_name = ""
        if req.variants:
            variant = next(
                (v for v in req.variants if re.search(v.pattern, reading.supplier_sw)),
                None,
            )
            if variant is not None:
                extract_regex = variant.extract or extract_regex
                levels = {**req.levels, **variant.levels}
                variant_name = variant.name

        required = levels.get(target)
        top_required = levels.get(requirements.profiles[-1]) if requirements.profiles else None
        if not reading.supplier_sw.strip():
            results.append(
                ModuleResult(
                    requirement=req, status=EMPTY, raw_name=reading.raw_name,
                    required=required, variant=variant_name,
                    meets=_meets(None, levels, requirements.profiles), levels=dict(levels),
                    reading=reading,
                )
            )
            continue
        extracted = _extract_number(reading.supplier_sw, extract_regex)
        if extracted is None or required is None:
            results.append(
                ModuleResult(
                    requirement=req, status=UNPARSEABLE,
                    raw_name=reading.raw_name, version=reading.supplier_sw,
                    required=required, variant=variant_name,
                    meets=_meets(None, levels, requirements.profiles), levels=dict(levels),
                    reading=reading,
                )
            )
            continue
        results.append(
            ModuleResult(
                requirement=req,
                status=OK if extracted >= required else OUTDATED,
                raw_name=reading.raw_name,
                version=reading.supplier_sw,
                extracted=extracted,
                required=required,
                level=_profile_level(extracted, levels, requirements.profiles),
                variant=variant_name,
                top_required=top_required,
                meets=_meets(extracted, levels, requirements.profiles),
                evidence_level=_evidence_level(extracted, levels, requirements.profiles),
                levels=dict(levels),
                reading=reading,
            )
        )

    # Everything not used above, including a second block with an already
    # matched code (a duplicate would otherwise vanish from the page silently)
    extra = [m for m in report.modules if not any(m is used for used in matched)]
    failing_critical = [r for r in results if r.status != OK and r.requirement.critical]

    # Already on Marlin: every marker module reached its marlin_level
    markers = [r for r in results if r.requirement.marlin_level is not None]
    on_marlin = bool(markers) and all(
        r.extracted is not None and r.extracted >= r.requirement.marlin_level for r in markers
    )
    if on_marlin:
        verdict = VERDICT_MARLIN
    elif failing_critical:
        verdict = VERDICT_ZEBRA
    else:
        verdict = VERDICT_READY

    profiles = list(requirements.profiles)
    complete_profile, top_evidence = _classify_levels(results, profiles)
    outcome = _outcome(verdict, complete_profile, top_evidence, target, profiles)
    marlin_results = [_marlin_result(req, report) for req in requirements.marlin_modules]
    return Evaluation(
        verdict=verdict,
        requirements_version=requirements.version,
        target_profile=target,
        results=results,
        profiles=profiles,
        extra_modules=extra,
        trim=trim,
        trim_name=TRIM_NAMES.get(trim, ""),
        outcome=outcome,
        complete_profile=complete_profile,
        top_evidence=top_evidence,
        marlin_results=marlin_results,
    )


def _marlin_result(req: MarlinRequirement, report: ParsedReport) -> MarlinResult:
    """Is this module at the level the Marlin update installs? Uses the first
    reading whose code matches; anything unreadable counts as not ok."""
    reading = next((m for m in report.modules if m.code.upper() in req.match), None)
    if reading is None:
        return MarlinResult(requirement=req, status=MISSING)
    if not reading.supplier_sw.strip():
        return MarlinResult(requirement=req, version="", status=EMPTY)
    extracted = _extract_number(reading.supplier_sw, req.extract)
    if extracted is None:
        return MarlinResult(requirement=req, version=reading.supplier_sw, status=UNPARSEABLE)
    ok = extracted >= req.marlin_level
    return MarlinResult(requirement=req, version=reading.supplier_sw, extracted=extracted,
                        ok=ok, status=OK if ok else OUTDATED)


def _classify_levels(results: list[ModuleResult], profiles: list[str]) -> tuple[str | None, str | None]:
    """(complete_profile, top_evidence): the highest profile that EVERY
    required module meets, and the highest profile ANY module gives evidence
    of. Only critical modules decide completeness; non-critical ones are
    informational, as in the ready/zebra verdict."""
    critical = [r for r in results if r.requirement.critical]
    complete = None
    for profile in profiles:
        judged = [r.meets.get(profile) for r in critical]
        if judged and all(v is not False for v in judged) and any(v is True for v in judged):
            complete = profile
    evidence = [r.evidence_level for r in results if r.evidence_level is not None]
    top = max(evidence, key=profiles.index) if evidence else None
    return complete, top


def _outcome(verdict: str, complete: str | None, top: str | None, target: str, profiles: list[str]) -> str:
    if verdict == VERDICT_MARLIN:
        return OUTCOME_MARLIN
    if complete is None or profiles.index(complete) < profiles.index(target):
        return OUTCOME_ZEBRA_TARGET
    if complete == profiles[-1]:
        return OUTCOME_FULL_TOP
    if top is not None and profiles.index(top) > profiles.index(complete):
        return OUTCOME_ZEBRA_TOP
    return OUTCOME_FULL_TARGET
