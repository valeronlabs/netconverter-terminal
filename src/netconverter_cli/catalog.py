"""What the connected server accepts, in one shape for both credential profiles.

``external`` credentials (an ``nck_*`` key or a Clerk sign-in) read
``GET /capabilities``: every vendor, source→target path and job type the full
API accepts. ``quick`` credentials (0.1.x Terminal Quick pilot keys) keep the
pilot's fixed ASA → Palo Alto surface. Menus are built from this object, never
from a list in the client.
"""

from __future__ import annotations

from dataclasses import dataclass, field

JOB_TYPES = ("convert", "validate", "optimize", "prescan")
QUICK_SOURCES = ("cisco_asa", "palo_alto_set", "palo_alto_xml", "palo_alto_panorama")
QUICK_LIMIT_BYTES = 50_000
DEVICE_TYPES = ("firewall", "router", "switch")

# Identity contract, not a promise that a server supports every directed path.
# Keep explicit device/format codes; bare Cisco/Juniper names are ambiguous.
VENDOR_IDENTITIES = {
    **dict.fromkeys(("cisco_asa", "palo_alto_xml", "palo_alto_set", "palo_alto_panorama",
                     "fortinet", "cisco_fmc", "check_point"), "firewall"),
    **dict.fromkeys(("cisco_ios_xe_router", "juniper_junos_router", "juniper_set_router"), "router"),
    **dict.fromkeys(("cisco_ios_xe_switch", "juniper_junos_switch", "juniper_set_switch",
                     "aruba_cx_switch", "aruba_os_switch", "cisco_nxos_switch"), "switch"),
}
# Identities the server emits but never reads: valid as a target, refused as a source.
TARGET_ONLY = frozenset({"cisco_nxos_switch"})
# Public submit-door aliases whose canonical code is an accepted identity.
# SCM, bare ArubaOS, Cisco and Juniper aliases do not open new submit paths.
VENDOR_ALIASES = {"aruba_cx": "aruba_cx_switch", "fortinet_fortigate": "fortinet",
                  "checkpoint": "check_point", "check-point": "check_point"}

# Names for codes a server response may not name (quick capabilities carry codes only).
NAMES = {
    "cisco_asa": "Cisco ASA",
    "palo_alto_set": "Palo Alto (Set)",
    "palo_alto_xml": "Palo Alto (XML)",
    "palo_alto_panorama": "Palo Alto (Panorama)",
}
# Human labels for option values shown in menus and the review card.
LABELS = {
    "vr": "Virtual router (vr)",
    "lr": "Logical router (lr)",
    "like_for_like": "Like for like",
    "ai_recommended": "AI recommended",
    "convert": "Convert",
    "validate": "Validate",
    "optimize": "Optimize",
    "prescan": "Prescan",
    "analyze": "Validate",
}
FIELD_LABELS = {
    "source_vendor": "Source",
    "target_vendor": "Target",
    "panos_target_version": "PAN-OS",
    "routing_engine": "Routing",
    "pipeline_mode": "Mode",
    "remove_unused_objects": "Unused objects",
    "panorama_device_group": "Device group",
    "panorama_template": "Template",
    "enable_appid": "App-ID",
    "app_id_implementation": "App-ID mode",
    "add_security_profiles": "Profiles",
    "log_all_rules": "Log all rules",
    "implicit_deny": "Explicit deny",
    "default_profile_group": "Profile group",
    "zone_mapping": "Zone mapping",
    "job_type": "Job",
    "file": "File",
}


def device_type_of(code: str) -> str:
    return VENDOR_IDENTITIES[normalize_vendor(code)]


def normalize_vendor(code: str) -> str:
    if not isinstance(code, str):
        raise ValueError("Use a supported vendor code with explicit router or switch identity")
    canonical = VENDOR_ALIASES.get(code, code)
    if canonical not in VENDOR_IDENTITIES:
        raise ValueError("Use a supported vendor code with explicit router or switch identity")
    return canonical


def submission_vendors(source: str, target: str | None) -> tuple[str, str | None]:
    source = normalize_vendor(source)
    if source in TARGET_ONLY:
        raise ValueError(f"{source} is a target only; it cannot be a source")
    target = normalize_vendor(target) if target is not None else None
    if target and device_type_of(source) != device_type_of(target):
        raise ValueError("Source and target must have the same device type")
    return source, target


def legacy_submission_vendors(source: str, target: str | None) -> tuple[tuple[str, str | None], ...]:
    """Equivalent v1 wire spellings only; preserve the old request fingerprint.

    v1 derived technology before normalization. Bare Aruba CX as a source was
    therefore a firewall request, not equivalent to a corrected switch request.
    Hyphenated aliases could not pass the v1 bridge's vendor-code syntax check.
    """
    source, target = submission_vendors(source, target)
    sources = [source] + [alias for alias, code in VENDOR_ALIASES.items()
                          if code == source and "-" not in alias and device_type_of(source) == "firewall"]
    targets = [target] + [alias for alias, code in VENDOR_ALIASES.items()
                          if code == target and "-" not in alias]
    return tuple((s, t) for s in sources for t in targets)


@dataclass
class Catalog:
    profile: str = "unknown"  # external | quick | unknown (not loaded yet)
    vendors: dict = field(default_factory=dict)  # code -> {name, device_type, roles, input}
    paths: list = field(default_factory=list)  # [(source, target)]
    job_types: tuple = ()
    limits: dict = field(default_factory=dict)
    remaining: dict = field(default_factory=dict)
    quick: dict = field(default_factory=dict)  # pilot-only conversion settings
    trial: bool = False

    @classmethod
    def from_external(cls, caps: dict) -> "Catalog":
        vendors = {}
        for item in caps.get("vendors") or []:
            if isinstance(item, dict) and isinstance(item.get("code"), str):
                code = item["code"]
                vendors[code] = {
                    "name": str(item.get("name") or NAMES.get(code) or code),
                    "device_type": item.get("device_type") or device_type_of(code),
                    "roles": list(item.get("roles") or []),
                    "input": item.get("input") or "text",
                }
        paths = [
            (p["source"], p["target"]) for p in caps.get("paths") or []
            if isinstance(p, dict) and p.get("source") in vendors and p.get("target") in vendors
        ]
        types = tuple(t for t in caps.get("job_types") or ("convert",) if t in JOB_TYPES)
        return cls("external", vendors, paths, types or ("convert",),
                   dict(caps.get("limits") or {}), {}, {}, bool(caps.get("trial")))

    @classmethod
    def from_quick(cls, caps: dict) -> "Catalog":
        targets = [t for t in caps.get("targets") or QUICK_SOURCES[1:]]
        vendors = {code: {"name": NAMES.get(code, code), "device_type": "firewall",
                          "roles": ["source"] + (["target"] if code in targets else []),
                          "input": "text"} for code in QUICK_SOURCES}
        paths = [("cisco_asa", t) for t in targets]
        quick = {k: caps[k] for k in ("panos_versions", "routing_engines", "pipeline_modes") if caps.get(k)}
        limits = {"max_config_bytes": (caps.get("limits") or {}).get("max_config_bytes") or QUICK_LIMIT_BYTES}
        return cls("quick", vendors, paths, JOB_TYPES, limits,
                   dict(caps.get("remaining") or {}), quick)

    # -- questions the menus ask ---------------------------------------------

    @property
    def loaded(self) -> bool:
        return bool(self.vendors)

    @property
    def max_bytes(self) -> int:
        if self.profile == "external":
            from .upload_policy import UploadPolicy
            return UploadPolicy.from_capabilities({"limits": self.limits}).max_bytes
        value = self.limits.get("max_config_bytes")
        return value if isinstance(value, int) and value > 0 else QUICK_LIMIT_BYTES

    def name(self, code: str | None) -> str:
        if not code:
            return "—"
        return self.vendors.get(code, {}).get("name") or NAMES.get(code) or code

    def sources(self, job_type: str = "convert") -> list[str]:
        """Sources this job type can start from, uploadable as a text file."""
        with_paths = {s for s, _ in self.paths}
        return [
            code for code, v in self.vendors.items()
            if "source" in v["roles"] and v["input"] == "text"
            and (job_type != "convert" or code in with_paths)
        ]

    def targets(self, source: str) -> list[str]:
        return [t for s, t in self.paths if s == source]

    def grouped(self, codes: list[str]) -> list[tuple[str, str]]:
        """(label, code) ordered firewall → router → switch, device type shown when ambiguous."""
        names = [self.name(c) for c in codes]
        out = []
        for kind in DEVICE_TYPES:
            for code in (c for c in codes if self.vendors.get(c, {}).get("device_type", "firewall") == kind):
                label = self.name(code)
                if names.count(label) > 1:
                    label += f" · {kind}"
                out.append((label, code))
        return out

    def supports(self, job_type: str) -> bool:
        return job_type in self.job_types

    def describe(self) -> str:
        if self.profile == "quick":
            return "Pilot key · ASA → Palo Alto"
        if not self.loaded:
            return ""
        return f"{len([v for v in self.vendors.values() if 'source' in v['roles']])} sources · {len(self.paths)} paths"


def label(value) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return LABELS.get(value, str(value)) if isinstance(value, str) else str(value)
