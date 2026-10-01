import grp
import os
import pwd
import stat
from pathlib import Path
from typing import Dict, Any, Optional, Tuple


def get_file_metadata(path_str: str) -> Dict[str, Any]:
    """
    Safely inspect file ownership, octal permissions, and symbolic mode.
    Returns status: 'OK', 'MISSING', or 'ERROR' along with details.
    """
    p = Path(path_str)
    if not p.exists():
        return {
            "status": "MISSING",
            "path": path_str,
            "exists": False,
            "mode_octal": None,
            "mode_str": None,
            "owner": None,
            "group": None,
            "uid": None,
            "gid": None,
            "error": "File does not exist"
        }

    try:
        st = p.stat()
        mode_octal = oct(stat.S_IMODE(st.st_mode))
        mode_str = stat.filemode(st.st_mode)

        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)

        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)

        return {
            "status": "OK",
            "path": path_str,
            "exists": True,
            "mode_octal": mode_octal,
            "mode_str": mode_str,
            "owner": owner,
            "group": group,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "is_world_writable": bool(st.st_mode & stat.S_IWOTH),
            "error": None
        }
    except PermissionError as e:
        return {
            "status": "ERROR",
            "path": path_str,
            "exists": True,
            "mode_octal": None,
            "mode_str": None,
            "owner": None,
            "group": None,
            "uid": None,
            "gid": None,
            "error": f"Permission denied: {e}"
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "path": path_str,
            "exists": True,
            "mode_octal": None,
            "mode_str": None,
            "owner": None,
            "group": None,
            "uid": None,
            "gid": None,
            "error": str(e)
        }


def is_permission_more_permissive(actual_octal_int: int, max_allowed_octal_int: int) -> bool:
    """
    Check if actual permissions have bits set that exceed max_allowed.
    Example: actual 0666 vs max 0644 -> returns True (violates security requirement)
    """
    # If any bit is set in actual that is NOT in max_allowed, it's more permissive
    return (actual_octal_int & ~max_allowed_octal_int) != 0
