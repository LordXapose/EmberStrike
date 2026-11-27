import re

from packaging.version import InvalidVersion, Version


_DEBIAN_EPOCH = re.compile(r"^(\d+):(.*)$")
_DEBIAN_REVISION = re.compile(r"^(.*)-([0-9][A-Za-z0-9+.~]*)$")
_DEBIAN_UPSTREAM = re.compile(r"^[0-9A-Za-z.+:~-]+$")
_DEBIAN_MARKER = re.compile(r"(?:\+deb\d|ubuntu\d)", re.IGNORECASE)
_RPM_MARKER = re.compile(r"(?:\.el\d|\.fc\d|\.amzn\d)", re.IGNORECASE)
_RPM_PLATFORM = re.compile(r"\b(?:rhel|red hat|centos|fedora|rocky|almalinux|amazon linux)\b", re.IGNORECASE)


def _debian_parts(value: str) -> tuple[int, str, str] | None:
    value = value.strip()
    epoch_match = _DEBIAN_EPOCH.match(value)
    epoch = int(epoch_match.group(1)) if epoch_match else 0
    version = epoch_match.group(2) if epoch_match else value
    if not version:
        return None

    upstream, separator, revision = version.rpartition("-")
    if not separator or not _DEBIAN_UPSTREAM.fullmatch(upstream):
        upstream, revision = version, "0"
    if not _DEBIAN_UPSTREAM.fullmatch(upstream) or not revision:
        return None
    return epoch, upstream, revision


def _debian_order(character: str) -> int:
    if character == "~":
        return -1
    if not character:
        return 0
    if character.isalpha():
        return ord(character)
    return ord(character) + 256


def _compare_debian_part(left: str, right: str) -> int:
    left_index = right_index = 0
    while left_index < len(left) or right_index < len(right):
        while (
            (left_index < len(left) and not left[left_index].isdigit())
            or (right_index < len(right) and not right[right_index].isdigit())
        ):
            left_character = left[left_index] if left_index < len(left) and not left[left_index].isdigit() else ""
            right_character = right[right_index] if right_index < len(right) and not right[right_index].isdigit() else ""
            left_order = _debian_order(left_character)
            right_order = _debian_order(right_character)
            if left_order != right_order:
                return -1 if left_order < right_order else 1
            if left_character:
                left_index += 1
            if right_character:
                right_index += 1

        while left_index < len(left) and left[left_index] == "0":
            left_index += 1
        while right_index < len(right) and right[right_index] == "0":
            right_index += 1
        left_start, right_start = left_index, right_index
        while left_index < len(left) and left[left_index].isdigit():
            left_index += 1
        while right_index < len(right) and right[right_index].isdigit():
            right_index += 1
        left_digits, right_digits = left[left_start:left_index], right[right_start:right_index]
        if len(left_digits) != len(right_digits):
            return -1 if len(left_digits) < len(right_digits) else 1
        if left_digits != right_digits:
            return -1 if left_digits < right_digits else 1
    return 0


def _is_distribution_package_version(value: str) -> bool:
    value = value.strip()
    if _RPM_MARKER.search(value):
        return False
    return bool(
        _DEBIAN_MARKER.search(value)
        or (
            (revision_match := _DEBIAN_REVISION.match(value))
            and revision_match.group(2).isdigit()
        )
    )


def compare_versions(left: str, right: str, platform: str = "") -> int | None:
    """Compare supported versions; return None when their schemes are unclear."""
    left = left.strip()
    right = right.strip()
    if not left or not right:
        return None

    debian_platform = bool(re.search(r"\b(?:debian|ubuntu)\b", platform, re.IGNORECASE))
    rpm_platform = bool(_RPM_PLATFORM.search(platform))
    left_package = _is_distribution_package_version(left)
    right_package = _is_distribution_package_version(right)
    if rpm_platform and (left_package or right_package or _RPM_MARKER.search(left) or _RPM_MARKER.search(right)):
        return None
    if left_package != right_package:
        return None
    use_debian_order = (
        debian_platform and (left_package or right_package or "~" in left or "~" in right)
        or left_package and right_package
        or "~" in left and "~" in right
    )
    if use_debian_order:
        if _RPM_MARKER.search(left) or _RPM_MARKER.search(right):
            return None
        left_parts, right_parts = _debian_parts(left), _debian_parts(right)
        if left_parts is None or right_parts is None:
            return None
        left_epoch, left_upstream, left_revision = left_parts
        right_epoch, right_upstream, right_revision = right_parts
        if left_epoch != right_epoch:
            return -1 if left_epoch < right_epoch else 1
        upstream_order = _compare_debian_part(left_upstream, right_upstream)
        return upstream_order or _compare_debian_part(left_revision, right_revision)

    try:
        left_version, right_version = Version(left), Version(right)
    except InvalidVersion:
        return None
    return (left_version > right_version) - (left_version < right_version)
