# app.py
# -----------------------------------------------------------------------------
# Vuln Findings Filter — filter/dedupe your CSV and surface patterns for reports.
# Now with optional Asset CSV enrichment and a revamped Pattern Explorer.
# Run:
#   pip install -U streamlit pandas python-dateutil
#   streamlit run app.py
# -----------------------------------------------------------------------------

import io
import re
import sys
import time
from typing import List, Optional, Tuple, Dict
from difflib import SequenceMatcher

import pandas as pd
import streamlit as st
from dateutil import parser as dtp  # kept for potential free-text fallbacks

# ---- Guard: prevent running without `streamlit run` --------------------------
try:
    from streamlit.runtime.scriptrunner import get_script_run_ctx  # type: ignore
    if get_script_run_ctx() is None:
        print("This is a Streamlit app. Start it with:  streamlit run app.py")
        raise SystemExit(0)
except Exception:
    if __name__ == "__main__" and not any("streamlit" in a for a in sys.argv):
        print("This is a Streamlit app. Start it with:  streamlit run app.py")
        raise SystemExit(0)
# -----------------------------------------------------------------------------

st.set_page_config(page_title="Vuln Findings Filter", layout="wide")

# =============================================================================
# LOAD DATA (Findings CSV)
# =============================================================================
st.sidebar.title("Load data")
src = st.sidebar.radio("Findings source", ["Upload CSV", "Local path"], index=0)
uploaded = None
csv_path = None
if src == "Upload CSV":
    uploaded = st.sidebar.file_uploader("Findings CSV file", type=["csv", "CSV"])
else:
    csv_path = st.sidebar.text_input("Findings CSV path", "findings.csv")

with st.sidebar.expander("Advanced CSV options (findings)", expanded=False):
    enc_choice_f = st.selectbox("Encoding", options=["Auto (utf-8-sig)", "utf-8", "latin-1"], index=0, key="enc_f")
    delim_mode_f = st.selectbox("Delimiter", options=["Auto-detect", "Comma ,", "Semicolon ;", "Pipe |", "Tab \\t"], index=0, key="delim_f")
    bad_lines_f = st.selectbox("On bad lines", options=["skip", "warn", "error"], index=0, key="bad_f")

def _encoding_value(s: str) -> str:
    if s == "Auto (utf-8-sig)":
        return "utf-8-sig"
    return s

def _delimiter_value(s: str) -> Optional[str]:
    mapping = {
        "Auto-detect": None,
        "Comma ,": ",",
        "Semicolon ;": ";",
        "Pipe |": "|",
        "Tab \\t": "\t",
    }
    return mapping[s]

@st.cache_data(show_spinner=False)
def load_findings_df(uploaded_file, path_str, encoding, delimiter, on_bad_lines):
    """
    Robust loader for findings:
    - Auto-detect delimiter (sep=None with engine='python') unless manual chosen
    - Tolerate BOM (utf-8-sig)
    - Skip/warn on bad lines
    - Read all columns as str initially, coerce some numerics, parse first_detected_on
    """
    src_local = uploaded_file if uploaded_file is not None else path_str
    read_kwargs = dict(
        dtype=str,
        encoding=encoding,
        on_bad_lines=on_bad_lines,
    )
    if delimiter is None:
        read_kwargs.update(sep=None, engine="python")
    else:
        read_kwargs.update(sep=delimiter)

    df = pd.read_csv(src_local, **read_kwargs).rename(columns=lambda c: c.strip())

    # Numeric columns
    for c in ("cvss_score", "base_score", "risk_score"):
        if c in df:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    # Datetime: parse as UTC, then drop tz (naive)
    if "first_detected_on" in df:
        dt = pd.to_datetime(df["first_detected_on"], errors="coerce", utc=True)
        df["first_detected_on"] = dt.dt.tz_convert("UTC").dt.tz_localize(None)

    # Strip text while preserving NaN
    def strip_preserve_na(x):
        return x.strip() if isinstance(x, str) else x

    for c in (
        "asset_mrn","vuln_mrn","vuln_id","type","summary",
        "asset_id","asset_name","space_id","space_mrn","space_name",
        "risk_value","risk_factors","risk_factor",
        "references","cvss_vector","cve_refs","cvss_severity","risk_severity"
    ):
        if c in df:
            df[c] = df[c].map(strip_preserve_na)

    return df

if (src == "Upload CSV" and uploaded is None) or (src == "Local path" and not csv_path):
    st.info("Load a findings CSV to begin.")
    st.stop()

try:
    df = load_findings_df(
        uploaded,
        csv_path,
        _encoding_value(enc_choice_f),
        _delimiter_value(delim_mode_f),
        bad_lines_f
    )
except Exception as e:
    st.error(f"Failed to load findings CSV: {e}")
    st.stop()

st.caption(f"Findings loaded: **{len(df):,}** rows, **{df.shape[1]}** columns.")

# =============================================================================
# OPTIONAL: LOAD ASSET CSV (enrichment)
# =============================================================================
st.sidebar.markdown("---")
st.sidebar.subheader("Assets data (optional)")
asset_src = st.sidebar.radio("Assets source", ["(none)", "Upload CSV", "Local path"], index=0)
asset_uploaded = None
asset_path = None
if asset_src == "Upload CSV":
    asset_uploaded = st.sidebar.file_uploader("Asset CSV file (optional)", type=["csv", "CSV"], key="asset_upl")
elif asset_src == "Local path":
    asset_path = st.sidebar.text_input("Asset CSV path", "assets.csv")

with st.sidebar.expander("Advanced CSV options (assets)", expanded=False):
    enc_choice_a = st.selectbox("Encoding", options=["Auto (utf-8-sig)", "utf-8", "latin-1"], index=0, key="enc_a")
    delim_mode_a = st.selectbox("Delimiter", options=["Auto-detect", "Comma ,", "Semicolon ;", "Pipe |", "Tab \\t"], index=0, key="delim_a")
    bad_lines_a = st.selectbox("On bad lines", options=["skip", "warn", "error"], index=0, key="bad_a")

@st.cache_data(show_spinner=False)
def load_assets_df(uploaded_file, path_str, encoding, delimiter, on_bad_lines):
    """
    Robust loader for assets:
    - All cols as str, then coerce known numerics and datetimes
    """
    if uploaded_file is None and not path_str:
        return None

    src_local = uploaded_file if uploaded_file is not None else path_str
    read_kwargs = dict(
        dtype=str,
        encoding=encoding,
        on_bad_lines=on_bad_lines,
    )
    if delimiter is None:
        read_kwargs.update(sep=None, engine="python")
    else:
        read_kwargs.update(sep=delimiter)

    adf = pd.read_csv(src_local, **read_kwargs).rename(columns=lambda c: c.strip())

    # Coerce numerics (common ones from your schema)
    num_cols = [
        "base_score", "risk_score", "risk_value",
        "security_base_score", "security_risk_score",
        "vuln_base_score", "vuln_risk_score"
    ]
    for c in num_cols:
        if c in adf:
            adf[c] = pd.to_numeric(adf[c], errors="coerce")

    # Datetimes
    for dc in ("updated_at", "score_updated_at"):
        if dc in adf:
            d = pd.to_datetime(adf[dc], errors="coerce", utc=True)
            adf[dc] = d.dt.tz_convert("UTC").dt.tz_localize(None)

    # Strip text while preserving NaN
    def strip_preserve_na(x):
        return x.strip() if isinstance(x, str) else x
    for c in adf.columns:
        adf[c] = adf[c].map(strip_preserve_na)

    return adf

assets_df = None
assets_loaded = False
if asset_src != "(none)":
    try:
        assets_df = load_assets_df(
            asset_uploaded,
            asset_path,
            _encoding_value(enc_choice_a),
            _delimiter_value(delim_mode_a),
            bad_lines_a
        )
        if assets_df is not None:
            st.caption(f"Assets loaded: **{len(assets_df):,}** rows, **{assets_df.shape[1]}** columns.")
            assets_loaded = True
    except Exception as e:
        st.warning(f"Asset CSV not loaded: {e}")

# =============================================================================
# QUICK PATTERN TEMPLATES (NEW FEATURE)
# =============================================================================
st.sidebar.markdown("---")
st.sidebar.subheader("Quick Patterns")

def apply_quick_pattern(df, pattern_name):
    """Apply pre-configured analysis patterns"""
    patterns = {
        "Critical Assets": {
            "filters": {"cvss_score": (7.0, 10.0)},
            "description": "High severity vulnerabilities"
        },
        "Old High Risk": {
            "filters": {"cvss_score": (7.0, 10.0), "days_open": (30, None)},
            "description": "High severity vulnerabilities open for 30+ days"
        },
        "Common Issues": {
            "filters": {"type": ["Misconfiguration", "Policy Violation"]},
            "description": "Common misconfiguration and policy issues"
        },
        "Network Issues": {
            "filters": {"type": ["Network", "Firewall", "SSL/TLS"]},
            "description": "Network and SSL/TLS related issues"
        },
        "Authentication": {
            "filters": {"type": ["Authentication", "Authorization", "Password"]},
            "description": "Authentication and authorization issues"
        }
    }
    
    if pattern_name not in patterns:
        return df, ""
    
    pattern = patterns[pattern_name]
    filtered_df = df.copy()
    
    # Apply days_open filter if needed
    if "days_open" in pattern["filters"] and "first_detected_on" in filtered_df.columns:
        filtered_df["days_open"] = (pd.Timestamp.now() - filtered_df["first_detected_on"]).dt.days
    
    # Apply all filters
    for col, value in pattern["filters"].items():
        if col not in filtered_df.columns:
            continue
        if isinstance(value, tuple):
            min_val, max_val = value
            if min_val is not None:
                filtered_df = filtered_df[filtered_df[col] >= min_val]
            if max_val is not None:
                filtered_df = filtered_df[filtered_df[col] <= max_val]
        elif isinstance(value, list):
            filtered_df = filtered_df[filtered_df[col].isin(value)]
    
    return filtered_df, pattern["description"]

selected_pattern = st.sidebar.selectbox(
    "Select quick pattern", 
    options=["(none)", "Critical Assets", "Old High Risk", "Common Issues", "Network Issues", "Authentication"]
)

# =============================================================================
# DEDUPE (Findings) — same as before
# =============================================================================
st.sidebar.markdown("---")
st.sidebar.subheader("Deduplication (findings)")

apply_dedupe = st.sidebar.checkbox("Apply dedupe", value=True)
all_cols_list = list(df.columns)

use_all_cols_as_key = st.sidebar.checkbox("Use ALL columns as key (exact duplicate removal)", value=False)

default_key = [c for c in ["asset_mrn","vuln_mrn","asset_id","vuln_id"] if c in df.columns] or []
key_cols = st.sidebar.multiselect(
    "Key columns (deduplicate on these)",
    options=all_cols_list,
    default=([] if use_all_cols_as_key else default_key),
    disabled=use_all_cols_as_key
)

st.sidebar.markdown("**Keeper order (sort, then keep first)**")
prio_df_init = pd.DataFrame({
    "column": all_cols_list,
    "use": [False]*len(all_cols_list),
    "ascending": [True]*len(all_cols_list),
    "priority": list(range(1, len(all_cols_list)+1))
})
for (col, asc, pr) in [("first_detected_on", True, 1), ("risk_score", False, 2), ("cvss_score", False, 3)]:
    if col in prio_df_init["column"].values:
        i = prio_df_init.index[prio_df_init["column"] == col][0]
        prio_df_init.at[i, "use"] = True
        prio_df_init.at[i, "ascending"] = asc
        prio_df_init.at[i, "priority"] = pr

prio_df = st.sidebar.data_editor(
    prio_df_init,
    use_container_width=True,
    num_rows="fixed",
    column_config={
        "column": st.column_config.TextColumn("Column", disabled=True),
        "use": st.column_config.CheckboxColumn("Use"),
        "ascending": st.column_config.CheckboxColumn("Ascending"),
        "priority": st.column_config.NumberColumn("Priority (1=highest)", min_value=1, step=1),
    },
    key="prio_editor_findings"
)

def dedupe_frame(frame: pd.DataFrame, key_cols: List[str], priorities: List[dict]) -> Tuple[pd.DataFrame, str, pd.DataFrame]:
    if priorities:
        by = [p["column"] for p in priorities]
        asc = [bool(p["ascending"]) for p in priorities]
        f_sorted = frame.sort_values(by=by, ascending=asc, kind="mergesort")
    else:
        f_sorted = frame

    if not key_cols:
        return f_sorted, "No key selected — dedupe skipped (only sorting applied).", pd.DataFrame(columns=f_sorted.columns)

    mask_dup = f_sorted.duplicated(subset=key_cols, keep="first")
    out = f_sorted.drop_duplicates(subset=key_cols, keep="first")
    dropped = f_sorted[mask_dup]

    if priorities:
        parts = [f"{p['column']} {'ASC' if p['ascending'] else 'DESC'} (prio {p['priority']})" for p in priorities]
        order_str = ", ".join(parts)
    else:
        order_str = "original order"
    return out, f"Deduped {len(f_sorted):,} → {len(out):,} using key {key_cols} (kept first after sorting by {order_str}).", dropped

if apply_dedupe:
    key_for_dedupe = all_cols_list.copy() if use_all_cols_as_key else key_cols.copy()
    prios_selected = prio_df[prio_df["use"]].sort_values("priority").to_dict(orient="records")
    work, dmsg, dropped_dupes = dedupe_frame(df, key_for_dedupe, prios_selected)
    st.success(dmsg)
    if not key_for_dedupe:
        st.info("Tip: Choose a key to actually remove duplicates.")
    with st.expander("Show dropped duplicates (preview)", expanded=False):
        if len(dropped_dupes) == 0:
            st.caption("No duplicates were dropped.")
        else:
            st.dataframe(dropped_dupes, use_container_width=True, height=260)
else:
    work = df.copy()
    st.info("Dedupe disabled.")

# =============================================================================
# FILTERS (same as before, regex-safe)
# =============================================================================
st.sidebar.markdown("---")
st.sidebar.subheader("Filters")

def num_bounds(series: pd.Series) -> Tuple[float, float]:
    x = pd.to_numeric(series, errors="coerce")
    return (float(x.min()), float(x.max())) if x.notna().any() else (0.0, 0.0)

def slider_or_info(label: str, full_rng: Optional[Tuple[float, float]], step: float):
    if full_rng and full_rng[0] != full_rng[1]:
        return st.sidebar.slider(label, full_rng[0], full_rng[1], full_rng, step=step)
    else:
        st.sidebar.caption(f"({label}: no usable numeric data)")
        return None

sev_vals = []
chosen_sev = None
if "cvss_severity" in work.columns:
    sev_vals = sorted(v for v in work["cvss_severity"].dropna().unique().tolist() if str(v).strip() != "")
    chosen_sev = st.sidebar.multiselect("cvss_severity", options=sev_vals, default=sev_vals, help="No filter until you deselect one or more severities.")

cvss_rng = None; cvss_full = None
if "cvss_score" in work.columns:
    cvss_full = num_bounds(work["cvss_score"])
    cvss_rng = slider_or_info("cvss_score", cvss_full, step=0.1)

risk_rng = None; risk_full = None
if "risk_score" in work.columns:
    risk_full = num_bounds(work["risk_score"])
    risk_rng = slider_or_info("risk_score", risk_full, step=0.1)

date_from = st.sidebar.date_input("first_detected_on from", value=None)
date_to   = st.sidebar.date_input("first_detected_on to",   value=None)

def sorted_unique(col):
    return sorted(v for v in work[col].dropna().unique().tolist())

space_pick = st.sidebar.multiselect("space_name equals…", options=sorted_unique("space_name") if "space_name" in work else [])
type_pick  = st.sidebar.multiselect("type equals…",       options=sorted_unique("type") if "type" in work else [])

st.sidebar.markdown("**Text contains / regex**")
case_sens = st.sidebar.checkbox("Case sensitive", value=False)
use_regex = st.sidebar.checkbox("Use regex", value=False)
asset_contains        = st.sidebar.text_input("asset_name contains…")
summary_contains      = st.sidebar.text_input("summary contains…")
risk_factors_contains = st.sidebar.text_input("risk_factors contains…")
cve_contains          = st.sidebar.text_input("cve_refs contains…")

def contains(series: pd.Series, needle: str, use_regex: bool, case_sens: bool) -> pd.Series:
    needle = (needle or "").strip()
    if not needle:
        return pd.Series([True] * len(series), index=series.index)
    if use_regex:
        flags = 0 if case_sens else re.IGNORECASE
        return series.fillna("").str.contains(needle, regex=True, flags=flags, na=False)
    return series.fillna("").str.contains(needle, case=case_sens, regex=False, na=False)

def contains_safe(series: pd.Series, needle: str, use_regex: bool, case_sens: bool, label: str) -> pd.Series:
    try:
        return contains(series, needle, use_regex, case_sens)
    except re.error as e:
        st.warning(f"Invalid regex in **{label}**: {e}")
        return pd.Series(True, index=series.index)

# Apply filters
flt = work

# Apply quick pattern if selected
if selected_pattern != "(none)":
    flt, pattern_desc = apply_quick_pattern(flt, selected_pattern)
    st.info(f"Applied pattern: {pattern_desc}")

if chosen_sev is not None and sev_vals and set(chosen_sev) != set(sev_vals):
    flt = flt[flt["cvss_severity"].isin(chosen_sev)]

if cvss_rng and cvss_full and cvss_rng != cvss_full:
    lo, hi = cvss_rng
    flt = flt[(flt["cvss_score"].between(lo, hi, inclusive="both")) | flt["cvss_score"].isna()]

if risk_rng and risk_full and risk_rng != risk_full:
    rlo, rhi = risk_rng
    flt = flt[(flt["risk_score"].between(rlo, rhi, inclusive="both")) | flt["risk_score"].isna()]

if "first_detected_on" in flt.columns:
    if date_from:
        flt = flt[flt["first_detected_on"] >= pd.to_datetime(date_from)]
    if date_to:
        flt = flt[flt["first_detected_on"] <= (pd.to_datetime(date_to) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1))]

if "space_name" in flt.columns and space_pick:
    flt = flt[flt["space_name"].isin(space_pick)]
if "type" in flt.columns and type_pick:
    flt = flt[flt["type"].isin(type_pick)]
if "asset_name" in flt.columns:
    flt = flt[contains_safe(flt["asset_name"], asset_contains, use_regex, case_sens, "asset_name")]
if "summary" in flt.columns:
    flt = flt[contains_safe(flt["summary"], summary_contains, use_regex, case_sens, "summary")]
if "risk_factors" in flt.columns:
    flt = flt[contains_safe(flt["risk_factors"], risk_factors_contains, use_regex, case_sens, "risk_factors")]
if "cve_refs" in flt.columns:
    flt = flt[contains_safe(flt["cve_refs"], cve_contains, use_regex, case_sens, "cve_refs")]

# =============================================================================
# VULNERABILITY AGING ANALYSIS (NEW FEATURE)
# =============================================================================
if "first_detected_on" in flt.columns:
    flt["days_open"] = (pd.Timestamp.now() - flt["first_detected_on"]).dt.days
    st.sidebar.markdown("**Vulnerability Aging**")
    min_days = int(flt["days_open"].min())
    max_days = int(flt["days_open"].max())
    days_open_filter = st.sidebar.slider("Days open filter", min_days, max_days, (min_days, max_days))
    flt = flt[flt["days_open"].between(days_open_filter[0], days_open_filter[1])]

# =============================================================================
# ENHANCED RISK SCORING (NEW FEATURE)
# =============================================================================
st.sidebar.markdown("---")
st.sidebar.subheader("Enhanced Risk Scoring")

# Find potential asset criticality columns
asset_crit_cols = [c for c in flt.columns if any(keyword in c.lower() for keyword in 
                   ['critical', 'importance', 'priority', 'tier', 'business'])]
asset_crit_cols = ["(none)"] + asset_crit_cols

asset_criticality_col = st.sidebar.selectbox(
    "Asset criticality column", 
    options=asset_crit_cols
)

if asset_criticality_col != "(none)":
    cvss_weight = st.sidebar.slider("CVSS weight", 0.0, 1.0, 0.7)
    asset_weight = st.sidebar.slider("Asset weight", 0.0, 1.0, 0.3)
    
    # Normalize asset criticality (assuming higher values = more critical)
    asset_crit_max = flt[asset_criticality_col].max()
    if asset_crit_max > 0:
        flt["asset_crit_normalized"] = flt[asset_criticality_col] / asset_crit_max
    else:
        flt["asset_crit_normalized"] = 0
    
    # Calculate enhanced risk score
    flt["enhanced_risk_score"] = (
        flt["cvss_score"].fillna(0) * cvss_weight + 
        flt["asset_crit_normalized"].fillna(0) * 10 * asset_weight
    )
    
    st.sidebar.caption(f"Enhanced risk score range: {flt['enhanced_risk_score'].min():.1f} - {flt['enhanced_risk_score'].max():.1f}")

# Quick header stats
c1, c2, c3, c4 = st.columns(4)
with c1: st.metric("Rows (filtered)", f"{len(flt):,}")
with c2: st.metric("Columns", f"{flt.shape[1]}")
with c3:
    aset_col = next((c for c in ["asset_name","asset_id","asset_mrn"] if c in flt.columns), None)
    st.metric("Distinct assets", f"{flt[aset_col].nunique():,}" if aset_col else "—")
with c4:
    sp_col = "space_name" if "space_name" in flt.columns else None
    st.metric("Distinct spaces", f"{flt[sp_col].nunique():,}" if sp_col else "—")

# =============================================================================
# ENRICHMENT (optional) — Join findings with assets
# =============================================================================
st.markdown("---")
st.header("Pattern Explorer")

# Sidebar controls for enrichment
st.sidebar.markdown("---")
st.sidebar.subheader("Enrichment (optional)")

def dedupe_dim(df_assets: pd.DataFrame, key: str, strategy: str) -> Tuple[pd.DataFrame, int]:
    if key not in df_assets.columns:
        return df_assets, 0
    before = len(df_assets)
    if strategy == "updated_at" and "updated_at" in df_assets.columns:
        df2 = df_assets.sort_values("updated_at", ascending=False, kind="mergesort")
    elif strategy == "score_updated_at" and "score_updated_at" in df_assets.columns:
        df2 = df_assets.sort_values("score_updated_at", ascending=False, kind="mergesort")
    else:
        df2 = df_assets
    out = df2.drop_duplicates(subset=[key], keep="first")
    return out, before - len(out)

def coalesce_series(primary: pd.Series, secondary: pd.Series) -> pd.Series:
    # prefer 'secondary' when notna, else primary
    return secondary.where(secondary.notna(), primary)

def join_enrich(
    df_findings: pd.DataFrame,
    df_assets: pd.DataFrame,
    left_key: str,
    right_key: str,
    join_type: str,
    overlap_policy: str,
    include_asset_cols: List[str]
) -> Tuple[pd.DataFrame, Dict[str, float]]:
    # Standardize join keys (string + strip) without mutating inputs
    lf = df_findings.copy()
    if left_key in lf.columns:
        lf[left_key] = lf[left_key].astype(str).str.strip()
    ra = df_assets.copy()
    if right_key in ra.columns:
        ra[right_key] = ra[right_key].astype(str).str.strip()

    overlaps = sorted(set(lf.columns) & set(ra.columns))
    needed_for_overlap = overlaps if overlap_policy in ("prefer_assets","coalesce") else []
    keep_cols = sorted(set([right_key] + include_asset_cols + needed_for_overlap))
    assets_small = ra[keep_cols].copy()

    merged = lf.merge(
        assets_small,
        how=join_type.lower(),
        left_on=left_key,
        right_on=right_key,
        suffixes=("", "_asset_tmp"),
        indicator=True
    )

    # Coverage diagnostics
    matches = int((merged["_merge"] == "both").sum())
    coverage_pct = (matches / len(lf) * 100.0) if len(lf) else 0.0
    merged.drop(columns=["_merge"], inplace=True)

    # Resolve overlaps
    for col in overlaps:
        if col == left_key or col == right_key:
            continue
        col_asset_tmp = f"{col}_asset_tmp"
        if col_asset_tmp not in merged.columns:
            continue
        if overlap_policy == "prefer_assets":
            merged[col] = merged[col_asset_tmp].where(merged[col_asset_tmp].notna(), merged[col])
        elif overlap_policy == "coalesce":
            merged[col] = coalesce_series(merged[col], merged[col_asset_tmp])
        # else prefer findings: do nothing
        merged.drop(columns=[col_asset_tmp], inplace=True)

    # Drop the right_key if it's a duplicate of left_key
    if right_key in merged.columns and right_key != left_key:
        merged.drop(columns=[right_key], inplace=True)

    diags = {
        "matches": matches,
        "coverage_pct": coverage_pct,
        "overlap_cols": len(overlaps),
        "added_cols": len([c for c in include_asset_cols if c in assets_small.columns and c not in overlaps and c != right_key]),
    }
    return merged, diags

# Enrichment UI (only enabled if assets are loaded)
enrichment_active = False
flt_enriched = flt
join_diags = {}
if assets_loaded and assets_df is not None and len(assets_df):
    # Suggested keys
    left_default = "asset_id" if "asset_id" in flt.columns else (next((c for c in ["asset_mrn","asset_name"] if c in flt.columns), None) or flt.columns[0])
    right_default = "asset_id" if "asset_id" in assets_df.columns else assets_df.columns[0]

    join_left_key = st.sidebar.selectbox("Findings key", options=list(flt.columns), index=list(flt.columns).index(left_default) if left_default in flt.columns else 0)
    join_right_key = st.sidebar.selectbox("Assets key", options=list(assets_df.columns), index=list(assets_df.columns).index(right_default) if right_default in assets_df.columns else 0)
    join_type = st.sidebar.radio("Join type", ["Left", "Inner"], index=0, horizontal=True)

    asset_dedupe_strategy = st.sidebar.selectbox(
        "If multiple asset rows share the key, dedupe by",
        options=["updated_at", "score_updated_at", "(first row)"],
        index=0
    )

    overlap_policy = st.sidebar.radio(
        "Overlapping columns policy",
        ["Prefer findings", "Prefer assets", "Coalesce (assets → findings)"],
        index=0
    )
    policy_map = {
        "Prefer findings": "prefer_findings",
        "Prefer assets": "prefer_assets",
        "Coalesce (assets → findings)": "coalesce",
    }
    policy_choice = policy_map[overlap_policy]

    # Asset-only columns candidates
    overlaps_now = set(flt.columns) & set(assets_df.columns)
    asset_only_cols = [c for c in assets_df.columns if c not in overlaps_now and c != join_right_key]
    default_asset_cols = [c for c in ["platform_name", "name", "labels"] if c in asset_only_cols]
    include_asset_cols = st.sidebar.multiselect(
        "Asset-only columns to append",
        options=asset_only_cols,
        default=default_asset_cols
    )

    # Dedupe assets by selected strategy/key
    dedup_key = join_right_key
    dedup_strategy = {"updated_at":"updated_at","score_updated_at":"score_updated_at","(first row)":"first"}[asset_dedupe_strategy]
    assets_dedup = assets_df
    dropped_n = 0
    if dedup_strategy in ("updated_at","score_updated_at"):
        assets_dedup, dropped_n = dedupe_dim(assets_df, dedup_key, dedup_strategy)

    # Perform join
    try:
        flt_enriched, join_diags = join_enrich(
            flt, assets_dedup, join_left_key, join_right_key, join_type,
            policy_choice, include_asset_cols
        )
        enrichment_active = True
    except Exception as e:
        st.warning(f"Enrichment join failed: {e}")
        flt_enriched = flt
        enrichment_active = False

    # Diagnostics & preview
    if enrichment_active:
        m1, m2 = st.columns([1,1])
        with m1:
            st.metric("Join matches", f"{join_diags.get('matches', 0):,}", f"{join_diags.get('coverage_pct', 0):.1f}% coverage")
        with m2:
            st.metric("Asset dedupe drops", f"{dropped_n:,}")
        st.caption("Note: Columns present in both tables are resolved by the selected policy — no duplicate columns are emitted.")
        with st.expander("Show join preview (top 50)", expanded=False):
            st.dataframe(flt_enriched.head(50), use_container_width=True, height=260)
else:
    st.sidebar.info("Load an asset CSV to enable enrichment (optional).")

# Working frame for downstream views (enriched if active)
current = flt_enriched if enrichment_active else flt

# =============================================================================
# SIMILAR FINDINGS GROUPING (NEW FEATURE)
# =============================================================================
st.subheader("Similar Findings Grouping")
st.caption("Group findings that are likely related with AWS domain tags")

# First, ensure we have domain information available
if "domain_df" not in st.session_state:
    st.warning("Please run AWS Domain Analysis first to add domain tags to similar findings.")
    domain_df = current.copy()
    domain_df["aws_domains"] = "Uncategorized"
else:
    domain_df = st.session_state.domain_df

similarity_col = st.selectbox(
    "Group by similarity", 
    options=["summary", "type", "risk_factors"] + [c for c in current.columns if c not in ["asset_name", "asset_id", "vuln_id"]],
    index=0
)
threshold = st.slider("Similarity threshold", 0.0, 1.0, 0.7)

def group_similar(df, col, threshold):
    """Group similar findings based on string similarity"""
    if col not in df.columns:
        return []
    
    groups = []
    processed_indices = set()
    df_values = df[col].fillna("").astype(str)
    
    # Create a copy of the dataframe to work with
    df_copy = df.copy()
    df_copy['temp_index'] = range(len(df_copy))
    
    for i in range(len(df_copy)):
        if i in processed_indices: 
            continue
        
        group_indices = [i]
        val1 = df_values.iloc[i]
        
        for j in range(i+1, len(df_copy)):
            if j in processed_indices: 
                continue
            
            val2 = df_values.iloc[j]
            if SequenceMatcher(None, val1, val2).ratio() > threshold:
                group_indices.append(j)
                processed_indices.add(j)
        
        groups.append(group_indices)
        processed_indices.add(i)
    
    return groups

def get_domain_for_index(idx, domain_df):
    """Get the domain for a given index"""
    if idx in domain_df.index:
        domains = domain_df.at[idx, "aws_domains"]
        if isinstance(domains, list):
            return domains[0] if domains else "Uncategorized"
        else:
            return domains if pd.notna(domains) else "Uncategorized"
    return "Uncategorized"

if st.button("Group Similar Findings"):
    with st.spinner("Grouping similar findings..."):
        similar_groups = group_similar(current, similarity_col, threshold)
        
        if similar_groups:
            st.success(f"Found {len(similar_groups)} groups of similar findings")
            
            # Show groups with more than 1 finding
            significant_groups = [g for g in similar_groups if len(g) > 1]
            
            if significant_groups:
                st.write(f"**{len(significant_groups)} groups with multiple findings:**")
                
                for i, group in enumerate(significant_groups[:10]):  # Show top 10
                    # Get the primary domain for this group
                    group_domains = []
                    for idx in group:
                        domain = get_domain_for_index(current.index[idx], domain_df)
                        if domain not in group_domains:
                            group_domains.append(domain)
                    
                    # Create domain tag
                    if len(group_domains) == 1:
                        domain_tag = f"🏷️ {group_domains[0]}"
                    else:
                        domain_tag = f"🏷️ {', '.join(group_domains[:2])}" + ("..." if len(group_domains) > 2 else "")
                    
                    with st.expander(f"Group {i+1}: {len(group)} findings - {domain_tag}"):
                        try:
                            # Use iloc with the indices from the group
                            group_df = current.iloc[group].copy()
                            
                            # Add domain information as a new column
                            group_df['AWS Domain'] = group_df.index.map(
                                lambda idx: get_domain_for_index(current.index[idx], domain_df)
                            )
                            
                            # Determine which columns to display
                            display_columns = []
                            preferred_columns = ["AWS Domain", "summary", "asset_name", "cvss_score", "risk_score", "type", "vuln_id"]
                            
                            for col in preferred_columns:
                                if col in group_df.columns:
                                    display_columns.append(col)
                            
                            # If no preferred columns found, use first few columns
                            if not display_columns:
                                display_columns = list(group_df.columns[:5])
                            
                            st.dataframe(group_df[display_columns], width='stretch')
                            
                        except IndexError:
                            # Fallback: use loc with the actual index values
                            try:
                                group_df = current.loc[current.index[group]].copy()
                                
                                # Add domain information
                                group_df['AWS Domain'] = group_df.index.map(
                                    lambda idx: get_domain_for_index(idx, domain_df)
                                )
                                
                                display_columns = []
                                preferred_columns = ["AWS Domain", "summary", "asset_name", "cvss_score", "risk_score", "type", "vuln_id"]
                                
                                for col in preferred_columns:
                                    if col in group_df.columns:
                                        display_columns.append(col)
                                
                                if not display_columns:
                                    display_columns = list(group_df.columns[:5])
                                
                                st.dataframe(group_df[display_columns], width='stretch')
                                
                            except (IndexError, KeyError):
                                st.error("Could not display this group due to indexing issues")
            else:
                st.info("No groups with multiple findings found at this threshold")
        else:
            st.warning("Could not group findings")
# =============================================================================
# AWS DOMAIN ANALYSIS (NEW FEATURE)
# =============================================================================
st.subheader("AWS Security Domain Analysis")
st.caption("Group findings by AWS security domains with interactive drilldown")

# Define AWS security domains and their associated keywords
aws_domains = {
    "Network Security": [
        "security group", "security groups", "sg-", "nacl", "network acl", "subnet", "route table", 
        "vpn", "direct connect", "transit gateway", "nat gateway", "elastic ip",
        "network firewall", "guardduty", "vpc flow logs", "internet gateway",
        "igw", "vpc peering", "vpc endpoint", "private link", "site-to-site vpn", "client vpn",
        "global accelerator", "dns firewall", "route53 resolver", "firewall manager",
        "shield", "waf", "ingress", "egress", "0.0.0.0/0", "::/0", "ip protocol",
        "port range", "tcp", "udp", "icmp", "http", "https", "ssh", "rdp", "ftp", "sftp",
        "smtp", "pop3", "imap", "dns", "ntp", "ldap", "snmp", "mysql", "postgres", "oracle",
        "sql server", "mongodb", "redis", "memcached", "port 21", "port 22", "port 23",
        "port 25", "port 53", "port 80", "port 123", "port 143", "port 443", "port 3389",
        "port 3306", "port 5432", "port 1521", "port 1433", "port 27017", "port 6379",
        "port 11211", "load balancers", "application load balancers", "classic load balancers",
        "access control lists", "network reachability", "tcp ports", "udp ports", "virtual gateway",
        "port probe", "network connection action", "dns request action", "portprobeunprotectedport",
        "denialofservice.tcp", "network acl", "security groups", "network access control",
        "restrict access", "incoming traffic", "outgoing traffic", "restrict incoming", "restrict outgoing",
        "ip address", "cidr", "protocol", "port", "network", "firewall rules", "network rules"
    ],
    "Identity and Access Management": [
        "iam", "role", "policy", "user", "group", "access key", "mfa", 
        "password policy", "root account", "cross-account", "assume role",
        "organizations", "scp", "service control policy", "saml", "oidc",
        "cognito", "directory service", "federation", "overlypermissiverole",
        "unauthorizedaccess", "credentialaccess", "persistence", "privilegeescalation",
        "iam policy", "role assumption", "access management", "identity federation",
        "access key", "active access key", "iam user", "user permissions", "role permissions"
    ],
    "Data Security": [
        "encryption", "kms", "s3", "ebs", "efs", "data at rest", "data in transit",
        "sse", "server-side encryption", "cmk", "customer managed key", "default encryption",
        "macie", "secrets manager", "certificate manager", "acm", "cloudhsm", "hsms",
        "encryption at rest", "kmskeyid", "sse-kms", "ebs encryption", "missing encryption",
        "data leaks", "sensitive materials", "plaintext", "data classification",
        "data protection", "key management", "certificate management"
    ],
    "Compute Security": [
        "ec2", "instance", "ami", "launch configuration", "autoscaling", 
        "lambda", "container", "eks", "ecs", "fargate", "batch", "lightsail",
        "outposts", "app runner", "snowball", "lambda functions", "ec2 instance",
        "ami security", "instance security", "container security", "serverless compute"
    ],
    "Database Security": [
        "rds", "dynamodb", "aurora", "redshift", "database", "db instance",
        "db snapshot", "db parameter group", "db security group", "db subnet group",
        "elasticache", "neptune", "documentdb", "timestream", "qls", "database encryption",
        "db access control", "database auditing", "sql injection", "database vulnerability"
    ],
    "Storage Security": [
        "s3", "efs", "fsx", "storage gateway", "backup", "snapshot",
        "bucket", "object storage", "file system", "volume", "glacier",
        "s3 glacier", "snow family", "snowball", "s3 bucket policy", "s3 access control",
        "object storage security", "file system security", "backup security"
    ],
    "Application Security": [
        "elastic beanstalk", "codebuild", "codepipeline", "codedeploy",
        "secrets manager", "parameter store", "certificate manager", "waf",
        "app runner", "codestar", "xray", "amplify", "injection flaws",
        "weak cryptography", "hardcoded credentials", "code vulnerability",
        "api security", "web application firewall", "application dependency",
        "code scanning", "application testing"
    ],
    "Serverless and API Security": [
        "lambda", "api gateway", "step functions", "eventbridge", "sqs", "sns",
        "serverless", "function", "trigger", "appsync", "amplify", "cognito",
        "lambda security", "api security", "event-driven security", "function permissions"
    ],
    "Monitoring and Logging": [
        "cloudtrail", "cloudwatch", "logs", "config", "alarm", "metric",
        "event", "audit", "log retention", "monitoring", "xray", "inspector",
        "log encryption", "audit logging", "security monitoring", "log analysis",
        "compliance monitoring", "performance monitoring"
    ],
    "Threat Detection and Response": [
        "guardduty", "inspector", "detective", "security hub", "macie",
        "backdoor", "credentialaccess", "cryptocurrency", "defenseevasion",
        "discovery", "execution", "exfiltration", "impact", "initialaccess",
        "pentest", "persistence", "policy", "privilegeescalation", "recon",
        "stealth", "trojan", "unauthorizedaccess", "bitcointool", "domain reputation",
        "command and control", "c&c", "mitre att&ck", "penetration testing",
        "reconnaissance", "denialofservice", "portprobeunprotectedport",
        "threat intelligence", "incident response", "security incident"
    ],
    "Compliance and Governance": [
        "compliance", "governance", "control tower", "security hub",
        "artifact", "config rule", "pci", "hipaa", "gdpr", "soc",
        "audit manager", "macie", "aws-foundational-security-best-practices",
        "cis-aws-foundations-benchmark", "compliance framework", "policy enforcement",
        "regulatory compliance", "security governance", "risk management"
    ],
    "Edge and Content Delivery": [
        "cloudfront", "route53", "global accelerator", "api gateway",
        "cdn", "dns security", "content delivery", "edge security",
        "dns security", "domain security", "edge computing"
    ],
    "Hybrid and On-Premises": [
        "outposts", "snowball", "storage gateway", "direct connect", "site-to-site vpn",
        "hybrid cloud", "on-premises", "edge location", "data migration"
    ],
    "Vulnerability Management": [
        "cves", "inspector score", "vulnerability intelligence", "package vulnerability",
        "code security", "automated reasoning", "machine learning", "vulnerability scanning",
        "patch management", "security assessment", "penetration testing",
        "vulnerability remediation", "security testing"
    ]
}

def categorize_aws_domain(text, domains):
    """
    Enhanced categorization function with priority-based matching
    """
    text_lower = str(text).lower()
    
    # Define priority order - more specific domains first
    domain_priority = [
        "Network Security",
        "Identity and Access Management",
        "Data Security",
        "Compute Security",
        "Database Security",
        "Storage Security",
        "Application Security",
        "Serverless and API Security",
        "Monitoring and Logging",
        "Threat Detection and Response",
        "Compliance and Governance",
        "Edge and Content Delivery",
        "Hybrid and On-Premises",
        "Vulnerability Management"
    ]
    
    # Count matches for each domain
    domain_matches = {}
    
    for domain, keywords in domains.items():
        match_count = 0
        for keyword in keywords:
            # Count occurrences of each keyword
            match_count += text_lower.count(keyword.lower())
        if match_count > 0:
            domain_matches[domain] = match_count
    
    # If no matches found, return Uncategorized
    if not domain_matches:
        return ["Uncategorized"]
    
    # Sort domains by priority first, then by match count
    sorted_domains = sorted(
        domain_matches.items(),
        key=lambda x: (domain_priority.index(x[0]) if x[0] in domain_priority else 999, -x[1])
    )
    
    # Return the top matching domain
    return [sorted_domains[0][0]]

def debug_categorization(text, domains):
    """Debug function to show why a finding is categorized a certain way"""
    text_lower = str(text).lower()
    
    st.write(f"Analyzing: {text}")
    st.write("Keyword matches:")
    
    for domain, keywords in domains.items():
        matches = []
        for keyword in keywords:
            if keyword.lower() in text_lower:
                matches.append(keyword)
        
        if matches:
            st.write(f"**{domain}**: {matches}")
    
    # Show the final categorization
    result = categorize_aws_domain(text, domains)
    st.write(f"**Final categorization**: {result}")

# Create tabs for different analysis modes
domain_tabs = st.tabs(["Domain Overview", "Domain Pattern Explorer", "Interactive Drilldown"])

with domain_tabs[0]:
    # Domain Overview Tab
    if st.button("Analyze AWS Domains", key="analyze_domains"):
        with st.spinner("Categorizing findings by AWS domains..."):
            # Create a copy of the current dataframe
            domain_df = current.copy()
            
            # Determine which columns to analyze for domain categorization
            text_columns = []
            for col in ["summary", "type", "risk_factors", "description", "title"]:
                if col in domain_df.columns:
                    text_columns.append(col)
            
            if not text_columns:
                st.warning("No suitable text columns found for domain analysis")
            else:
                # Apply domain categorization
                domain_df["aws_domains"] = domain_df[text_columns].apply(
                    lambda row: categorize_aws_domain(" ".join(row.dropna().astype(str)), aws_domains), 
                    axis=1
                )
                
                # Explode the domains to create one row per domain
                domain_exploded = domain_df.explode("aws_domains")
                
                # Count findings by domain
                domain_counts = domain_exploded["aws_domains"].value_counts().reset_index()
                domain_counts.columns = ["Domain", "Count"]
                
                # Create visualization
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.subheader("Findings by AWS Security Domain")
                    st.bar_chart(domain_counts.set_index("Domain"))
                
                with col2:
                    st.subheader("Domain Statistics")
                    st.dataframe(domain_counts, width='stretch')
                
                # Store the domain data in session state for use in other tabs
                st.session_state.domain_df = domain_df
                st.session_state.domain_exploded = domain_exploded
                st.session_state.domain_counts = domain_counts
                
                # Add a section to review and override categorizations
                with st.expander("Review and Override Categorizations"):
                    st.write("Review findings that may be incorrectly categorized:")
                    
                    # Find findings with potential misclassifications
                    misclassified = []
                    for idx, row in domain_df.iterrows():
                        text = " ".join([str(row[col]) for col in text_columns if pd.notna(row[col])])
                        categories = categorize_aws_domain(text, aws_domains)
                        
                        # Check for security group findings not in Network Security
                        if "security group" in text.lower() and "Network Security" not in categories:
                            misclassified.append((idx, text, categories))
                    
                    if misclassified:
                        st.write(f"Found {len(misclassified)} potentially misclassified findings:")
                        
                        for idx, text, categories in misclassified[:5]:  # Show first 5
                            st.write(f"Index {idx}: {text[:100]}...")
                            st.write(f"Current category: {categories}")
                            
                            # Allow manual reclassification
                            new_category = st.selectbox(
                                "Reclassify to:",
                                options=list(aws_domains.keys()) + ["Uncategorized"],
                                key=f"reclassify_{idx}"
                            )
                            
                            if st.button(f"Update", key=f"update_{idx}"):
                                # Update the categorization
                                domain_df.at[idx, "aws_domains"] = [new_category]
                                st.success(f"Updated finding {idx} to {new_category}")
                                st.rerun()
                    else:
                        st.write("No obvious misclassifications found.")
                
                # Debug section
                with st.expander("Debug Categorization"):
                    st.write("Test the categorization logic with sample findings:")
                    
                    # Get some sample findings
                    sample_findings = domain_df.head(3)
                    
                    for idx, row in sample_findings.iterrows():
                        text = " ".join([str(row[col]) for col in text_columns if pd.notna(row[col])])
                        with st.expander(f"Debug Finding {idx}"):
                            debug_categorization(text, aws_domains)

with domain_tabs[1]:
    # Domain Pattern Explorer Tab
    if "domain_exploded" in st.session_state:
        domain_exploded = st.session_state.domain_exploded
        
        st.subheader("Pattern Explorer within AWS Domains")
        
        # Select domain to explore
        selected_domain = st.selectbox(
            "Select a domain to explore patterns",
            options=domain_exploded["aws_domains"].unique().tolist(),
            key="domain_explore_select"
        )
        
        # Filter findings by selected domain
        domain_findings = domain_exploded[domain_exploded["aws_domains"] == selected_domain]
        
        st.write(f"**{len(domain_findings)} findings** in {selected_domain}")
        
        # Column selection for display
        st.markdown("##### Select columns to display")
        available_cols = list(domain_findings.columns)
        selected_display_cols = st.multiselect(
            "Columns to display", 
            options=available_cols,
            default=["summary", "asset_name", "cvss_score", "risk_score"] if all(col in available_cols for col in ["summary", "asset_name", "cvss_score", "risk_score"]) else available_cols[:5],
            key="domain_display_cols"
        )
        
        # Pattern Explorer UI (similar to the main Pattern Explorer)
        st.markdown("##### Group by columns within this domain")
        domain_group_cols = st.multiselect(
            "Group by (any number of columns)",
            options=list(domain_findings.columns),
            default=[c for c in ["type", "cvss_severity"] if c in domain_findings.columns],
            key="domain_group_cols"
        )
        
        # Aggregation options
        st.markdown("##### Aggregations")
        domain_agg_choices = {
            "count_rows": "Count rows",
            "nunique_col": "Distinct values of a column",
            "sum_col": "Sum of a numeric column",
            "mean_col": "Mean of a numeric column",
            "max_col": "Max of a numeric column",
            "min_col": "Min of a numeric column",
        }
        domain_agg_selected = st.multiselect(
            "Metrics to compute", 
            options=list(domain_agg_choices.keys()), 
            default=["count_rows"],
            key="domain_agg_selected"
        )
        
        # Columns to apply metrics on
        domain_num_cols = [c for c in domain_findings.columns if pd.to_numeric(domain_findings[c], errors="coerce").notna().any()]
        domain_any_cols = list(domain_findings.columns)
        
        domain_metric_targets = {}
        if any(x.endswith("_col") for x in domain_agg_selected):
            with st.expander("Pick columns for selected metrics", expanded=True):
                if "nunique_col" in domain_agg_selected:
                    domain_metric_targets["nunique_col"] = st.selectbox(
                        "nunique() column", 
                        options=domain_any_cols, 
                        index=domain_any_cols.index("asset_id") if "asset_id" in domain_any_cols else 0,
                        key="domain_nunique_col"
                    )
                for m in ("sum_col","mean_col","max_col","min_col"):
                    if m in domain_agg_selected:
                        domain_metric_targets[m] = st.selectbox(
                            f"{m.split('_')[0]}() column", 
                            options=domain_num_cols or domain_any_cols, 
                            index=0, 
                            key=f"domain_pick_{m}"
                        )
        
        # Compute button
        if st.button("Compute domain patterns", type="primary", key="compute_domain_patterns"):
            with st.spinner("Computing patterns..."):
                t0 = time.perf_counter()
                try:
                    domain_pattern_result = pattern_rollup_multi(
                        domain_findings, domain_group_cols, domain_agg_selected, domain_metric_targets
                    )
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    
                    if len(domain_pattern_result) > 0:
                        st.caption(f"Computed on **{len(domain_findings):,} rows in **{elapsed_ms:.0f} ms**.")
                        
                        # Display results
                        st.dataframe(domain_pattern_result, width='stretch')
                        
                        # Export domain patterns
                        csv_buf_pat = io.StringIO()
                        domain_pattern_result.to_csv(csv_buf_pat, index=False)
                        st.download_button(
                            "Download Domain Pattern CSV", 
                            csv_buf_pat.getvalue(),
                            file_name=f"{selected_domain.lower().replace(' ', '_')}_patterns.csv", 
                            mime="text/csv"
                        )
                    else:
                        st.info("No patterns found with the selected criteria.")
                except Exception as e:
                    st.warning(f"Pattern computation failed: {e}")
        
        # Display domain findings with selected columns
        if selected_display_cols:
            st.subheader(f"All Findings in {selected_domain}")
            st.dataframe(domain_findings[selected_display_cols], width='stretch')
    else:
        st.info("Please analyze AWS domains first in the Domain Overview tab.")

with domain_tabs[2]:
    # Interactive Drilldown Tab
    if "domain_exploded" in st.session_state:
        domain_exploded = st.session_state.domain_exploded
        
        st.subheader("Interactive Drilldown")
        
        # Select domain to drill down
        selected_domain = st.selectbox(
            "Select a domain for drilldown",
            options=domain_exploded["aws_domains"].unique().tolist(),
            key="drilldown_domain"
        )
        
        # Filter findings by selected domain
        domain_findings = domain_exploded[domain_exploded["aws_domains"] == selected_domain]
        
        # Column selection for display
        st.markdown("##### Select columns to display")
        available_cols = list(domain_findings.columns)
        selected_display_cols = st.multiselect(
            "Columns to display", 
            options=available_cols,
            default=["summary", "asset_name", "cvss_score", "risk_score"] if all(col in available_cols for col in ["summary", "asset_name", "cvss_score", "risk_score"]) else available_cols[:5],
            key="drilldown_cols"
        )
        
        if selected_display_cols:
            # Display findings with interactive elements
            st.subheader(f"Findings in {selected_domain}")
            
            # Add a clickable column for drilldown
            display_df = domain_findings[selected_display_cols].copy()
            
            # Add a clickable index column
            display_df["_index"] = display_df.index
            
            # Display the dataframe with row selection
            selected_row = st.dataframe(
                display_df,
                width='stretch',
                height=420,
                on_select="rerun",
                selection_mode="single-row"
            )
            
            # Check if a row was selected
            if hasattr(selected_row, "selection") and selected_row.selection.rows:
                selected_idx = selected_row.selection.rows[0]
                selected_finding = domain_findings.iloc[selected_idx]
                
                st.markdown("---")
                st.subheader("🔍 Finding Details")
                
                # Create a nice layout for finding details
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    # Main finding information
                    st.markdown("### 📋 Overview")
                    
                    # Summary with emphasis
                    if "summary" in selected_finding.index and pd.notna(selected_finding["summary"]):
                        st.markdown(f"**Summary:** {selected_finding['summary']}")
                    
                    # Asset information
                    asset_info = []
                    for col in ["asset_name", "asset_id", "asset_mrn"]:
                        if col in selected_finding.index and pd.notna(selected_finding[col]):
                            asset_info.append(f"**{col}:** {selected_finding[col]}")
                    if asset_info:
                        st.markdown("### 🏷️ Asset Information")
                        for info in asset_info:
                            st.markdown(info)
                    
                    # Type and category
                    if "type" in selected_finding.index and pd.notna(selected_finding["type"]):
                        st.markdown(f"### 📂 Type")
                        st.markdown(f"**{selected_finding['type']}**")
                    
                    # Risk factors
                    if "risk_factors" in selected_finding.index and pd.notna(selected_finding["risk_factors"]):
                        st.markdown("### ⚠️ Risk Factors")
                        st.markdown(selected_finding["risk_factors"])
                
                with col2:
                    # Risk scoring information
                    st.markdown("### 📊 Risk Assessment")
                    
                    # CVSS Score with color coding
                    if "cvss_score" in selected_finding.index and pd.notna(selected_finding["cvss_score"]):
                        cvss = selected_finding["cvss_score"]
                        if cvss >= 9.0:
                            cvss_color = "🔴"
                            cvss_level = "Critical"
                        elif cvss >= 7.0:
                            cvss_color = "🟠"
                            cvss_level = "High"
                        elif cvss >= 4.0:
                            cvss_color = "🟡"
                            cvss_level = "Medium"
                        else:
                            cvss_color = "🟢"
                            cvss_level = "Low"
                        
                        st.markdown(f"{cvss_color} **CVSS Score:** {cvss}")
                        st.markdown(f"**Severity:** {cvss_level}")
                    
                    # Risk Score
                    if "risk_score" in selected_finding.index and pd.notna(selected_finding["risk_score"]):
                        st.markdown(f"**Risk Score:** {selected_finding['risk_score']}")
                    
                    # Enhanced Risk Score if available
                    if "enhanced_risk_score" in selected_finding.index and pd.notna(selected_finding["enhanced_risk_score"]):
                        st.markdown(f"**Enhanced Risk:** {selected_finding['enhanced_risk_score']:.1f}")
                    
                    # First detected date
                    if "first_detected_on" in selected_finding.index and pd.notna(selected_finding["first_detected_on"]):
                        detected_date = pd.to_datetime(selected_finding["first_detected_on"])
                        days_open = (pd.Timestamp.now() - detected_date).days
                        st.markdown(f"### 📅 Timeline")
                        st.markdown(f"**First Detected:** {detected_date.strftime('%Y-%m-%d')}")
                        st.markdown(f"**Days Open:** {days_open}")
                        
                        if days_open > 90:
                            st.markdown("⚠️ **Aging Finding**")
                    
                    # CVE information
                    if "cve_refs" in selected_finding.index and pd.notna(selected_finding["cve_refs"]):
                        st.markdown("### 🔐 CVE References")
                        st.markdown(f"`{selected_finding['cve_refs']}`")
                
                # Additional details in expandable sections
                with st.expander("📄 Additional Details"):
                    for col in domain_findings.columns:
                        if col not in ["summary", "asset_name", "asset_id", "asset_mrn", "type", "risk_factors", 
                                      "cvss_score", "risk_score", "enhanced_risk_score", "first_detected_on", "cve_refs"]:
                            if pd.notna(selected_finding[col]):
                                st.markdown(f"**{col}:** {selected_finding[col]}")
                
                # Action buttons for the selected finding
                st.markdown("---")
                st.subheader("🛠️ Actions")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("🔍 Find Similar Findings", key="find_similar"):
                        # Find similar findings based on semantic similarity
                        similarity_col = st.selectbox(
                            "Find similar based on",
                            options=["summary", "type", "risk_factors"] + [c for c in domain_findings.columns if c not in ["asset_name", "asset_id", "vuln_id"]],
                            key="similarity_col"
                        )
                        
                        if similarity_col in domain_findings.columns:
                            selected_value = str(selected_finding[similarity_col])
                            
                            # Find similar findings using semantic similarity (80% threshold)
                            similar_findings = []
                            for idx, row in domain_findings.iterrows():
                                if idx != selected_idx:  # Skip the selected finding itself
                                    compare_value = str(row[similarity_col])
                                    similarity = SequenceMatcher(None, selected_value, compare_value).ratio()
                                    if similarity >= 0.8:  # 80% threshold
                                        similar_findings.append((idx, similarity, row))
                            
                            # Sort by similarity score (descending)
                            similar_findings.sort(key=lambda x: x[1], reverse=True)
                            
                            if similar_findings:
                                st.write(f"🎯 Found {len(similar_findings)} semantically similar findings (80%+ similarity):")
                                
                                for idx, similarity, row in similar_findings:
                                    with st.expander(f"Similarity: {similarity:.1%} - {str(row.get('summary', 'N/A'))[:100]}..."):
                                        # Display key information
                                        col_a, col_b = st.columns([3, 1])
                                        with col_a:
                                            if "summary" in row.index:
                                                st.markdown(f"**Summary:** {row['summary']}")
                                            if "asset_name" in row.index:
                                                st.markdown(f"**Asset:** {row['asset_name']}")
                                        with col_b:
                                            if "cvss_score" in row.index:
                                                st.markdown(f"**CVSS:** {row['cvss_score']}")
                                            if "risk_score" in row.index:
                                                st.markdown(f"**Risk:** {row['risk_score']}")
                            else:
                                st.info("No semantically similar findings found (80%+ threshold)")
                
                with col2:
                    if st.button("🏷️ Filter by Asset", key="filter_by_asset"):
                        # Filter all findings by the asset of the selected finding
                        asset_col = None
                        for col in ["asset_name", "asset_id", "asset_mrn"]:
                            if col in selected_finding.index and pd.notna(selected_finding[col]):
                                asset_col = col
                                break
                        
                        if asset_col:
                            asset_value = selected_finding[asset_col]
                            asset_findings = current[current[asset_col] == asset_value]
                            
                            st.write(f"🏷️ All findings for {asset_col}: `{asset_value}`")
                            st.dataframe(asset_findings[selected_display_cols], width='stretch')
                
                with col3:
                    if st.button("📂 Filter by Type", key="filter_by_type"):
                        # Filter all findings by the type of the selected finding
                        if "type" in selected_finding.index and pd.notna(selected_finding["type"]):
                            type_value = selected_finding["type"]
                            type_findings = current[current["type"] == type_value]
                            
                            st.write(f"📂 All findings of type: `{type_value}`")
                            st.dataframe(type_findings[selected_display_cols], width='stretch')
    else:
        st.info("Please analyze AWS domains first in the Domain Overview tab.")
# =============================================================================
# PATTERN EXPLORER (interactive, multi-agg, drilldown, trends, charts)
# =============================================================================
st.subheader("Group, aggregate, and explore patterns")
st.caption("Uses your current filtered data" + (" (enriched)" if enrichment_active else ""))

# ---- Helper: build a readable key for a group row
def _group_key(row: pd.Series, group_cols: List[str]) -> str:
    parts = []
    for c in group_cols:
        val = row[c]
        parts.append(f"{c}={val!r}")
    return " | ".join(parts)

# ---- UI: pick groupers
group_cols = st.multiselect(
    "Group by (any number of columns)",
    options=list(current.columns),
    default=[c for c in ["space_name","cvss_severity"] if c in current.columns]
)

# ---- UI: multi-aggregation
st.markdown("##### Aggregations")
agg_choices = {
    "count_rows": "Count rows",
    "nunique_col": "Distinct values of a column",
    "sum_col": "Sum of a numeric column",
    "mean_col": "Mean of a numeric column",
    "max_col": "Max of a numeric column",
    "min_col": "Min of a numeric column",
}
agg_selected = st.multiselect("Metrics to compute", options=list(agg_choices.keys()), default=["count_rows"])

# Columns to apply metrics on (if needed)
num_cols = [c for c in current.columns if pd.to_numeric(current[c], errors="coerce").notna().any()]
any_cols = list(current.columns)

metric_targets = {}
if any(x.endswith("_col") for x in agg_selected):
    with st.expander("Pick columns for selected metrics", expanded=True):
        if "nunique_col" in agg_selected:
            metric_targets["nunique_col"] = st.selectbox("nunique() column", options=any_cols, index=any_cols.index("asset_id") if "asset_id" in any_cols else 0)
        for m in ("sum_col","mean_col","max_col","min_col"):
            if m in agg_selected:
                metric_targets[m] = st.selectbox(f"{m.split('_')[0]}() column", options=num_cols or any_cols, index=0, key=f"pick_{m}")

# ---- Compute
btn_cols = st.columns([1,1,1,3])
with btn_cols[0]:
    compute_patterns = st.button("Compute patterns", type="primary")
with btn_cols[1]:
    topn = st.number_input("Top N", min_value=1, value=50, help="Limit displayed groups for convenience.")
with btn_cols[2]:
    sort_metric = st.selectbox("Sort by metric", options=["auto (first metric)","(none)"], index=0)

pattern_result = None
elapsed_ms = None
flatten_cols = []

def pattern_rollup_multi(df_base: pd.DataFrame, group_cols: List[str],
                         selected: List[str], targets: Dict[str,str]) -> pd.DataFrame:
    if not group_cols or not selected:
        return pd.DataFrame()

    # Prepare working frame with numeric conversions for selected target columns
    dfw = df_base.copy()
    for m, col in targets.items():
        if col in dfw.columns:
            dfw[col] = pd.to_numeric(dfw[col], errors="coerce")

    gb = dfw.groupby(group_cols, dropna=False)

    # Build aggregations
    agg_spec = {}
    out_col_order = []

    if "count_rows" in selected:
        # pandas shortcut: size()
        cnt = gb.size().rename("count")
        agg_spec["__COUNT_ONLY__"] = cnt  # placeholder to merge later
        out_col_order.append("count")

    for key, label in [("nunique_col","nunique"), ("sum_col","sum"), ("mean_col","mean"), ("max_col","max"), ("min_col","min")]:
        if key in selected:
            col = targets.get(key)
            if not col:
                continue
            s = gb[col]
            if label == "nunique":
                series = s.nunique(dropna=True).rename(f"nunique({col})")
            else:
                series = s.agg(label).rename(f"{label}({col})")
            agg_spec[key] = series
            out_col_order.append(series.name)

    # Combine into a single frame
    pieces = []
    for k, ser in agg_spec.items():
        if k == "__COUNT_ONLY__":
            pieces.append(ser)
        else:
            pieces.append(ser)
    out = pd.concat(pieces, axis=1).reset_index()

    # Sort
    by = None
    if sort_metric == "auto (first metric)":
        # first metric column after the groupers
        metric_cols = [c for c in out.columns if c not in group_cols]
        by = metric_cols[0] if metric_cols else None
    if by:
        out = out.sort_values(by=by, ascending=False, kind="mergesort")

    return out

if compute_patterns:
    t0 = time.perf_counter()
    try:
        pattern_result = pattern_rollup_multi(current, group_cols, agg_selected, metric_targets)
    except Exception as e:
        st.warning(f"Pattern computation failed: {e}")
        pattern_result = None
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

# ---- Interactive table (search + quick filters)
if pattern_result is not None and len(pattern_result):
    st.caption(f"Computed on **{len(current):,}** rows in **{elapsed_ms:.0f} ms**.")
    # Global search
    q = st.text_input("Search in results (substring, case-insensitive)", value="")
    pr = pattern_result.copy()
    if q.strip():
        ql = q.strip().lower()
        mask_any = pd.Series(False, index=pr.index)
        for col in pr.columns:
            mask_any |= pr[col].astype(str).str.lower().str.contains(ql, na=False)
        pr = pr[mask_any]

    # Optional quick filters for each group column
    with st.expander("Quick filters", expanded=False):
        for gc in group_cols:
            vals = ["(all)"] + sorted(pr[gc].dropna().astype(str).unique().tolist())
            pick = st.selectbox(f"{gc} equals…", options=vals, index=0, key=f"flt_{gc}")
            if pick != "(all)":
                pr = pr[pr[gc].astype(str) == pick]

    # Top-N
    if topn and len(pr) > topn:
        pr = pr.head(int(topn))

    # Display
    st.dataframe(pr, use_container_width=True, height=420)

    # ---- Drilldown: select a row and show underlying findings
    st.markdown("###### Drill down")
    if len(pr):
        # build display keys
        pr = pr.copy()
        pr["_grp_key"] = pr.apply(lambda r: _group_key(r, group_cols), axis=1)
        choice = st.selectbox("Choose a group to drill into", options=["(pick)"] + pr["_grp_key"].tolist(), index=0)
        if choice != "(pick)":
            r = pr[pr["_grp_key"] == choice].iloc[0]
            # Build boolean mask across all groupers
            mask = pd.Series(True, index=current.index)
            for c in group_cols:
                # Match exact value (including NaN handling)
                val = r[c]
                if pd.isna(val):
                    mask &= current[c].isna()
                else:
                    mask &= current[c] == val
            drilled = current[mask]

            st.caption(f"Underlying rows for **{choice}** — {len(drilled):,} rows")
            st.dataframe(drilled, use_container_width=True, height=420)

            # =============================================================================
            # CVE QUICK LOOKUP (NEW FEATURE)
            # =============================================================================
            if "cve_refs" in drilled.columns:
                st.subheader("CVE Quick Lookup")
                cve_list = drilled["cve_refs"].dropna().unique()
                if len(cve_list) > 0:
                    selected_cve = st.selectbox("Select CVE", options=cve_list)
                    
                    # Simple CVE info display
                    st.markdown(f"**CVE:** {selected_cve}")
                    
                    # Extract CVE number for display
                    cve_match = re.search(r'CVE-\d{4}-\d+', selected_cve, re.IGNORECASE)
                    if cve_match:
                        cve_num = cve_match.group(0)
                        st.markdown(f"**CVE Number:** {cve_num}")
                        
                        # Show severity if available
                        if "cvss_severity" in drilled.columns:
                            severity = drilled[drilled["cve_refs"] == selected_cve]["cvss_severity"].iloc[0]
                            st.markdown(f"**Severity:** {severity}")
                        
                        # Show CVSS score if available
                        if "cvss_score" in drilled.columns:
                            score = drilled[drilled["cve_refs"] == selected_cve]["cvss_score"].iloc[0]
                            st.markdown(f"**CVSS Score:** {score}")
                        
                        st.markdown("**Description:**")
                        st.info("CVE details would be fetched from NVD database in a production implementation")
                        st.markdown("**Remediation:**")
                        st.info("Remediation guidance would be displayed here in a production implementation")

            # Download drilled rows
            _buf = io.StringIO()
            drilled.to_csv(_buf, index=False)
            st.download_button("Download CSV (drilldown rows)", _buf.getvalue(),
                               file_name="drilldown_rows.csv", mime="text/csv")

    # ---- Pivot (heatmap-ready) like before, but auto-suggest metrics
    if len(group_cols) in (2, 3):
        st.markdown("###### Pivot / Heatmap")
        metric_cols = [c for c in pr.columns if c not in group_cols + ["_grp_key"]]
        if metric_cols:
            pivot_metric = st.selectbox("Value", options=metric_cols, index=0, key="pivot_metric")
            show_pivot = st.checkbox("Show pivot grid", value=False)
            if show_pivot:
                try:
                    if len(group_cols) == 2:
                        piv = pr.pivot(index=group_cols[0], columns=group_cols[1], values=pivot_metric)
                    else:
                        g1, g2, g3 = group_cols[:3]
                        pr2 = pr.copy()
                        pr2["_colkey_"] = pr2[g2].astype(str) + " | " + pr2[g3].astype(str)
                        piv = pr2.pivot(index=g1, columns="_colkey_", values=pivot_metric)
                    st.dataframe(piv, use_container_width=True, height=420)
                except Exception as e:
                    st.info(f"Pivot could not be formed: {e}")

    # ---- Bar chart of top groups (first metric)
    st.markdown("###### Quick chart")
    metric_cols = [c for c in pr.columns if c not in group_cols + ["_grp_key"]]
    if metric_cols and group_cols:
        chart_metric = st.selectbox("Bar metric", options=metric_cols, index=0)
        # Build label from group cols
        pr["_label_"] = pr.apply(lambda r: " | ".join(str(r[c]) for c in group_cols), axis=1)
        chart_data = pr[["_label_", chart_metric]].rename(columns={"_label_":"group"})
        st.bar_chart(chart_data.set_index("group"))

    # ---- Export patterns CSV
    csv_buf_pat = io.StringIO()
    pattern_result.to_csv(csv_buf_pat, index=False)
    st.download_button("Download Pattern CSV", csv_buf_pat.getvalue(),
                       file_name="pattern_explorer.csv", mime="text/csv")

else:
    st.info("Pick group columns and click **Compute patterns** to see results.")

# =============================================================================
# REMEDIATION PRIORITY MATRIX (NEW FEATURE)
# =============================================================================
st.markdown("---")
st.subheader("Remediation Priority Matrix")
st.caption("Visualize findings by effort vs impact")

# Find potential effort columns
effort_cols = [c for c in current.columns if any(keyword in c.lower() for keyword in 
               ['effort', 'complexity', 'time', 'cost', 'remediation'])]
effort_cols = ["(none)"] + effort_cols

effort_col = st.selectbox("Effort estimate column", options=effort_cols)
impact_col = st.selectbox("Impact column", options=["cvss_score", "risk_score", "enhanced_risk_score"] if "enhanced_risk_score" in current.columns else ["cvss_score", "risk_score"])

if effort_col != "(none)" and impact_col in current.columns:
    # Create quadrants
    effort_median = current[effort_col].median()
    impact_median = current[impact_col].median()
    
    high_effort = current[effort_col] > effort_median
    high_impact = current[impact_col] > impact_median
    
    quick_wins = current[~high_effort & high_impact]
    major_projects = current[high_effort & high_impact]
    fill_ins = current[~high_effort & ~high_impact]
    thankless = current[high_effort & ~high_impact]
    
    # Display quadrants
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🟢 Quick Wins (High Impact, Low Effort)")
        st.write(f"{len(quick_wins)} findings")
        if len(quick_wins) > 0:
            st.dataframe(quick_wins[["summary", "asset_name", impact_col, effort_col]].head(10), use_container_width=True)
        
        st.markdown("### 🟡 Fill-ins (Low Impact, Low Effort)")
        st.write(f"{len(fill_ins)} findings")
        if len(fill_ins) > 0:
            st.dataframe(fill_ins[["summary", "asset_name", impact_col, effort_col]].head(10), use_container_width=True)
    
    with col2:
        st.markdown("### 🔴 Major Projects (High Impact, High Effort)")
        st.write(f"{len(major_projects)} findings")
        if len(major_projects) > 0:
            st.dataframe(major_projects[["summary", "asset_name", impact_col, effort_col]].head(10), use_container_width=True)
        
        st.markdown("### ⚪ Thankless Tasks (Low Impact, High Effort)")
        st.write(f"{len(thankless)} findings")
        if len(thankless) > 0:
            st.dataframe(thankless[["summary", "asset_name", impact_col, effort_col]].head(10), use_container_width=True)
    
    # Export quick wins
    if len(quick_wins) > 0:
        csv_buf = io.StringIO()
        quick_wins.to_csv(csv_buf, index=False)
        st.download_button("Download Quick Wins CSV", csv_buf.getvalue(),
                           file_name="quick_wins.csv", mime="text/csv")
else:
    st.info("Select both effort and impact columns to generate the priority matrix")

# =============================================================================
# ASSET RISK PROFILE (NEW FEATURE)
# =============================================================================
st.markdown("---")
st.subheader("Asset Risk Profile")
st.caption("Risk concentration per asset")

if "asset_name" in current.columns:
    # Group by asset and calculate risk metrics
    asset_risk = current.groupby("asset_name").agg({
        "cvss_score": ["max", "mean", "count"],
        "risk_score": ["max", "mean"],
        "vuln_id": "count"
    }).round(2)
    
    # Flatten column names
    asset_risk.columns = ['_'.join(col).strip() for col in asset_risk.columns.values]
    asset_risk = asset_risk.reset_index()
    
    # Add enhanced risk if available
    if "enhanced_risk_score" in current.columns:
        enhanced_risk = current.groupby("asset_name")["enhanced_risk_score"].agg(["max", "mean"]).round(2)
        enhanced_risk.columns = ["enhanced_risk_max", "enhanced_risk_mean"]
        asset_risk = asset_risk.merge(enhanced_risk, on="asset_name")
    
    # Sort by max CVSS score
    asset_risk = asset_risk.sort_values("cvss_score_max", ascending=False)
    
    st.dataframe(asset_risk, use_container_width=True, height=400)
    
    # Export asset risk profile
    csv_buf = io.StringIO()
    asset_risk.to_csv(csv_buf, index=False)
    st.download_button("Download Asset Risk Profile", csv_buf.getvalue(),
                       file_name="asset_risk_profile.csv", mime="text/csv")
else:
    st.info("No asset_name column available for risk profiling")

# ---- Trend mode --------------------------------------------------------------
st.markdown("---")
st.markdown("### Trend view (time buckets)")
if "first_detected_on" in current.columns:
    with st.expander("Build a time series", expanded=False):
        freq = st.selectbox("Bucket size", options=["D","W","M","Q"], index=2,
                            format_func=lambda x: {"D":"Daily","W":"Weekly","M":"Monthly","Q":"Quarterly"}[x])
        trend_metric = st.selectbox("Metric", options=["count_rows","sum_col","mean_col","max_col","min_col","nunique_col"], index=0)
        trend_target = None
        if trend_metric != "count_rows":
            pool = num_cols if trend_metric != "nunique_col" else any_cols
            if not pool:
                st.info("No suitable columns found for the chosen metric.")
            else:
                trend_target = st.selectbox("Column", options=pool, index=0, key="trend_target")

        by_one_dim = st.selectbox("Optional: split by a categorical column", options=["(none)"] + [c for c in current.columns if c != "first_detected_on"], index=0)

        build_trend = st.button("Compute trend")
        if build_trend:
            dfw = current.copy()
            dfw["__bucket__"] = pd.Grouper(level=None)
            # Ensure datetime
            ts = pd.to_datetime(dfw["first_detected_on"], errors="coerce")
            dfw = dfw[~ts.isna()].copy()
            dfw["first_detected_on"] = ts.dropna()
            dfw["__bucket__"] = dfw["first_detected_on"].dt.to_period(freq).dt.to_timestamp()

            if by_one_dim != "(none)":
                groupers = ["__bucket__", by_one_dim]
            else:
                groupers = ["__bucket__"]

            gb = dfw.groupby(groupers, dropna=False)
            if trend_metric == "count_rows":
                ts_out = gb.size().rename("count").reset_index()
                value_col = "count"
            elif trend_metric == "nunique_col":
                ts_out = gb[trend_target].nunique(dropna=True).rename(f"nunique({trend_target})").reset_index()
                value_col = f"nunique({trend_target})"
            else:
                dfw[trend_target] = pd.to_numeric(dfw[trend_target], errors="coerce")
                label = trend_metric.split("_")[0]
                ts_out = gb[trend_target].agg(label).reset_index().rename(columns={trend_target: f"{label}({trend_target})"})
                value_col = f"{label}({trend_target})"

            st.caption(f"{len(ts_out):,} aggregated points")
            st.dataframe(ts_out, use_container_width=True, height=360)

            # Chart
            if by_one_dim == "(none)":
                chart_df = ts_out.set_index("__bucket__")[value_col]
                st.line_chart(chart_df)
            else:
                # pivot to columns for line chart
                piv = ts_out.pivot(index="__bucket__", columns=by_one_dim, values=value_col)
                st.line_chart(piv)

            # Export
            _buf2 = io.StringIO()
            ts_out.to_csv(_buf2, index=False)
            st.download_button("Download CSV (trend)", _buf2.getvalue(),
                               file_name="trend_timeseries.csv", mime="text/csv")
else:
    st.info("No `first_detected_on` column available for trends.")

# =============================================================================
# VULNERABILITY INTELLIGENCE (NEW FEATURE)
# =============================================================================
st.subheader("Vulnerability Intelligence")
st.caption("Analyze CVEs and vulnerabilities across your infrastructure")

# Create tabs for vulnerability analysis
vuln_tabs = st.tabs(["Vulnerability Dashboard", "CVE Explorer", "Asset Patching Groups"])

with vuln_tabs[0]:
    # Vulnerability Dashboard Tab
    st.subheader("📊 Vulnerability Overview")
    
    if st.button("Analyze Vulnerabilities", key="analyze_vulns"):
        with st.spinner("Analyzing vulnerabilities..."):
            # Group by vulnerability ID
            vuln_groups = current.groupby('vuln_id').agg({
                'asset_id': 'nunique',
                'asset_name': 'unique',
                'space_name': 'unique',
                'cvss_score': 'first',
                'cvss_severity': 'first',
                'summary': 'first',
                'first_detected_on': 'min',
                'resolved_on': lambda x: x.notna().sum(),
                'risk_score': 'sum'
            }).reset_index()
            
            vuln_groups.columns = ['vuln_id', 'affected_assets', 'asset_names', 'spaces_affected', 
                                  'cvss_score', 'cvss_severity', 'summary', 'first_detected', 
                                  'resolved_count', 'aggregate_risk']
            
            # Calculate remediation rate
            vuln_groups['remediation_rate'] = vuln_groups['resolved_count'] / vuln_groups['affected_assets']
            
            # Store in session state
            st.session_state.vuln_groups = vuln_groups
            
            # Top vulnerabilities by affected assets
            top_vulns = vuln_groups.nlargest(10, 'affected_assets')
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.subheader("🔥 Top 10 Critical Vulnerabilities")
                st.dataframe(top_vulns[['vuln_id', 'affected_assets', 'cvss_score', 'cvss_severity']], width='stretch')
            
            with col2:
                st.subheader("📈 Risk Distribution")
                severity_dist = vuln_groups['cvss_severity'].value_counts()
                st.dataframe(severity_dist.reset_index(), width='stretch')
            
            # Risk heatmap
            st.subheader("🎯 Risk Impact Matrix")
            risk_matrix = vuln_groups.copy()
            risk_matrix['risk_category'] = pd.cut(
                risk_matrix['cvss_score'], 
                bins=[0, 4, 7, 10], 
                labels=['Low', 'Medium', 'High']
            )
            risk_matrix['impact_category'] = pd.cut(
                risk_matrix['affected_assets'], 
                bins=[0, 2, 5, 100], 
                labels=['Limited', 'Moderate', 'Widespread']
            )
            
            # Create pivot table for heatmap
            heatmap_data = risk_matrix.groupby(['risk_category', 'impact_category']).size().unstack(fill_value=0)
            st.dataframe(heatmap_data, width='stretch')

with vuln_tabs[1]:
    # CVE Explorer Tab
    if "vuln_groups" in st.session_state:
        vuln_groups = st.session_state.vuln_groups
        
        st.subheader("🔍 CVE Explorer")
        
        # Search and filter
        col1, col2, col3 = st.columns(3)
        
        with col1:
            search_cve = st.text_input("Search CVE ID or keywords", key="cve_search")
        
        with col2:
            severity_filter = st.multiselect(
                "Filter by severity",
                options=vuln_groups['cvss_severity'].unique().tolist(),
                key="severity_filter"
            )
        
        with col3:
            min_assets = st.number_input("Min affected assets", min_value=1, value=1, key="min_assets")
        
        # Apply filters
        filtered_vulns = vuln_groups.copy()
        
        if search_cve:
            filtered_vulns = filtered_vulns[
                filtered_vulns['vuln_id'].str.contains(search_cve, case=False, na=False) |
                filtered_vulns['summary'].str.contains(search_cve, case=False, na=False)
            ]
        
        if severity_filter:
            filtered_vulns = filtered_vulns[filtered_vulns['cvss_severity'].isin(severity_filter)]
        
        filtered_vulns = filtered_vulns[filtered_vulns['affected_assets'] >= min_assets]
        
        st.write(f"**{len(filtered_vulns)}** vulnerabilities match your criteria")
        
        # Display vulnerabilities with expandable details
        for idx, vuln in filtered_vulns.iterrows():
            with st.expander(f"🔍 {vuln['vuln_id']} - {vuln['cvss_severity']} - {vuln['affected_assets']} assets"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"**Summary:** {vuln['summary']}")
                    st.markdown(f"**First Detected:** {vuln['first_detected']}")
                    
                    # Fix: Handle None values in spaces_affected
                    spaces_list = vuln['spaces_affected'] if vuln['spaces_affected'] is not None else []
                    if isinstance(spaces_list, list):
                        spaces_str = ', '.join(str(s) for s in spaces_list if s is not None)
                    else:
                        spaces_str = str(spaces_list) if spaces_list else "N/A"
                    st.markdown(f"**Spaces Affected:** {spaces_str}")
                    
                    # Get common risk factors
                    vuln_findings = current[current['vuln_id'] == vuln['vuln_id']]
                    if 'risk_factors' in vuln_findings.columns:
                        risk_factors = vuln_findings['risk_factors'].dropna().tolist()
                        if risk_factors:
                            st.markdown("**Common Risk Factors:**")
                            for rf in risk_factors[:3]:  # Show top 3
                                st.markdown(f"• {rf}")
                
                with col2:
                    st.markdown("### 📊 Metrics")
                    st.markdown(f"**CVSS Score:** {vuln['cvss_score']}")
                    st.markdown(f"**Severity:** {vuln['cvss_severity']}")
                    st.markdown(f"**Affected Assets:** {vuln['affected_assets']}")
                    st.markdown(f"**Aggregate Risk:** {vuln['aggregate_risk']}")
                    st.markdown(f"**Remediation Rate:** {vuln['remediation_rate']:.1%}")
                
                # Show affected assets
                with st.expander(f"📋 Affected Assets ({len(vuln['asset_names'])})"):
                    assets_data = []
                    for asset_id in vuln_findings['asset_id'].unique():
                        asset_info = vuln_findings[vuln_findings['asset_id'] == asset_id].iloc[0]
                        assets_data.append({
                            'Asset ID': asset_id,
                            'Asset Name': asset_info['asset_name'],
                            'Space': asset_info['space_name'],
                            'Risk Score': asset_info['risk_score'],
                            'Status': 'Resolved' if pd.notna(asset_info['resolved_on']) else 'Open'
                        })
                    
                    assets_df = pd.DataFrame(assets_data)
                    st.dataframe(assets_df, width='stretch')
    else:
        st.info("Please analyze vulnerabilities first in the Vulnerability Dashboard tab.")

with vuln_tabs[2]:
    # Asset Patching Groups Tab
    st.subheader("🔧 Asset Patching Groups")
    st.caption("Group assets that can be patched together")
    
    def group_by_cve(df):
        """Group assets that share the same CVEs"""
        cve_groups = df.groupby('vuln_id').agg({
            'asset_id': 'unique',
            'asset_name': 'unique',
            'space_name': 'unique',
            'cvss_score': 'first',
            'summary': 'first'
        }).reset_index()
        
        # Filter for CVEs affecting multiple assets
        multi_asset_cves = cve_groups[cve_groups['asset_id'].str.len() > 1]
        return multi_asset_cves
    
    def extract_tech_indicators(asset_name):
        """Extract technology indicators from asset names"""
        indicators = []
        asset_lower = str(asset_name).lower()
        
        if 'lambda' in asset_lower:
            indicators.append('lambda')
        if 'rds' in asset_lower or 'database' in asset_lower:
            indicators.append('database')
        if 'eks' in asset_lower or 'kubernetes' in asset_lower:
            indicators.append('kubernetes')
        if 'ec2' in asset_lower or 'instance' in asset_lower:
            indicators.append('ec2')
        if 'function' in asset_lower:
            indicators.append('serverless')
        
        return indicators
    
    def group_by_technology(df):
        """Group assets by technology stack"""
        df['tech_indicators'] = df['asset_name'].apply(extract_tech_indicators)
        
        tech_groups = df.explode('tech_indicators').groupby('tech_indicators').agg({
            'asset_id': 'unique',
            'vuln_id': 'unique',
            'cvss_score': 'mean'
        }).reset_index()
        
        return tech_groups
    
    def normalize_risk_factors(risk_factors):
        """Normalize risk factors"""
        if pd.isna(risk_factors):
            return []
        
        factors = str(risk_factors).lower()
        factors = re.split(r'[,;|]', factors)
        return [f.strip() for f in factors if f.strip()]
    
    def group_by_risk_factors(df):
        """Group assets by risk factor patterns"""
        df['normalized_risk_factors'] = df['risk_factors'].apply(normalize_risk_factors)
        
        risk_groups = df.explode('normalized_risk_factors').groupby('normalized_risk_factors').agg({
            'asset_id': 'unique',
            'vuln_id': 'unique',
            'cvss_score': 'mean'
        }).reset_index()
        
        return risk_groups
    
    def create_patch_groups(df):
        """Create intelligent patch groups using multiple criteria"""
        patch_groups = []
        
        # Strategy 1: Direct CVE sharing
        cve_groups = group_by_cve(df)
        for _, cve_group in cve_groups.iterrows():
            patch_groups.append({
                'group_type': 'CVE-Based',
                'group_id': cve_group['vuln_id'],
                'assets': cve_group['asset_id'],
                'patch_reason': f"Share {cve_group['vuln_id']}: {cve_group['summary'][:100]}...",
                'priority': cve_group['cvss_score'],
                'spaces': cve_group['space_name'],
                'shared_cves': [cve_group['vuln_id']]
            })
        
        # Strategy 2: Technology similarity
        tech_groups = group_by_technology(df)
        for _, tech_group in tech_groups.iterrows():
            if len(tech_group['asset_id']) > 1:
                patch_groups.append({
                    'group_type': 'Technology-Based',
                    'group_id': f"tech_{tech_group['tech_indicators']}",
                    'assets': tech_group['asset_id'],
                    'patch_reason': f"Similar {tech_group['tech_indicators']} technology stack",
                    'priority': tech_group['cvss_score'],
                    'shared_cves': tech_group['vuln_id']
                })
        
        # Strategy 3: Risk factor patterns
        risk_groups = group_by_risk_factors(df)
        for _, risk_group in risk_groups.iterrows():
            if len(risk_group['asset_id']) > 1:
                patch_groups.append({
                    'group_type': 'Risk-Factor-Based',
                    'group_id': f"risk_{risk_group['normalized_risk_factors']}",
                    'assets': risk_group['asset_id'],
                    'patch_reason': f"Share risk factor: {risk_group['normalized_risk_factors']}",
                    'priority': risk_group['cvss_score'],
                    'shared_cves': risk_group['vuln_id']
                })
        
        return patch_groups
    
    if st.button("Generate Patch Groups", key="generate_patch_groups"):
        with st.spinner("Analyzing assets for patching groups..."):
            patch_groups = create_patch_groups(current)
            
            if not patch_groups:
                st.info("No multi-asset patch groups identified.")
            else:
                st.success(f"Found {len(patch_groups)} patch groups")
                
                # Sort by priority
                patch_groups.sort(key=lambda x: x['priority'], reverse=True)
                
                # Group statistics
                st.subheader("📊 Patch Group Statistics")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Total Groups", len(patch_groups))
                
                with col2:
                    total_assets = sum(len(g['assets']) for g in patch_groups)
                    st.metric("Total Assets in Groups", total_assets)
                
                with col3:
                    avg_priority = sum(g['priority'] for g in patch_groups) / len(patch_groups)
                    st.metric("Average Priority", f"{avg_priority:.1f}")
                
                # Display groups
                st.subheader("🔧 Recommended Patch Groups")
                
                for i, group in enumerate(patch_groups[:15]):  # Show top 15
                    with st.expander(f"📦 Group {i+1}: {group['group_type']} - Priority {group['priority']:.1f}"):
                        col1, col2 = st.columns([3, 1])
                        
                        with col1:
                            st.markdown(f"**🎯 Patch Reason:** {group['patch_reason']}")
                            
                            # Show assets in this group
                            assets_data = []
                            for asset_id in group['assets']:
                                asset_info = current[current['asset_id'] == asset_id].iloc[0]
                                assets_data.append({
                                    'Asset ID': asset_id,
                                    'Asset Name': asset_info['asset_name'],
                                    'Space': asset_info['space_name'],
                                    'CVSS': asset_info['cvss_score']
                                })
                            
                            assets_df = pd.DataFrame(assets_data)
                            st.dataframe(assets_df, width='stretch')
                        
                        with col2:
                            st.markdown("**📋 Group Info:**")
                            st.markdown(f"**Type:** {group['group_type']}")
                            st.markdown(f"**Assets:** {len(group['assets'])}")
                            st.markdown(f"**Priority:** {group['priority']:.1f}")
                            
                            if 'spaces' in group:
                                st.markdown(f"**Spaces:** {len(group['spaces'])}")
                            
                            # Export button
                            if st.button(f"📥 Export", key=f"export_patch_group_{i}"):
                                export_data = []
                                for asset_id in group['assets']:
                                    asset_data = current[current['asset_id'] == asset_id].to_dict('records')
                                    for record in asset_data:
                                        record['patch_group'] = f"{group['group_type']}_{i+1}"
                                        record['patch_reason'] = group['patch_reason']
                                        record['group_priority'] = group['priority']
                                        export_data.append(record)
                                
                                export_df = pd.DataFrame(export_data)
                                csv = export_df.to_csv(index=False)
                                st.download_button(
                                    f"Download Group {i+1}",
                                    csv,
                                    file_name=f"patch_group_{i+1}.csv",
                                    mime="text/csv"
                                )
                
                # Export all groups
                st.markdown("---")
                if st.button("📥 Export All Patch Groups", key="export_all_patch_groups"):
                    all_export_data = []
                    for i, group in enumerate(patch_groups):
                        for asset_id in group['assets']:
                            asset_data = current[current['asset_id'] == asset_id].to_dict('records')
                            for record in asset_data:
                                record['patch_group'] = f"{group['group_type']}_{i+1}"
                                record['patch_reason'] = group['patch_reason']
                                record['group_priority'] = group['priority']
                                all_export_data.append(record)
                    
                    all_export_df = pd.DataFrame(all_export_data)
                    all_csv = all_export_df.to_csv(index=False)
                    st.download_button(
                        "Download All Groups CSV",
                        all_csv,
                        file_name="all_patch_groups.csv",
                        mime="text/csv"
                    )
# =============================================================================
# COLUMNS & SORTING (applies to current working frame)
# =============================================================================
st.markdown("---")
st.markdown("### Columns & sorting")
all_cols = list(current.columns)

# Persist selection across reruns; reset when schema changes
if st.session_state.get("_cols_sig") != tuple(all_cols):
    st.session_state["show_cols"] = all_cols.copy()
    st.session_state["_cols_sig"] = tuple(all_cols)

btn1, btn2, btn3 = st.columns(3)
with btn1:
    if st.button("Select all"):
        st.session_state["show_cols"] = all_cols.copy()
with btn2:
    if st.button("Select none"):
        st.session_state["show_cols"] = []
with btn3:
    if st.button("Invert selection"):
        st.session_state["show_cols"] = [c for c in all_cols if c not in st.session_state["show_cols"]]

show_cols = st.multiselect("Columns to display/export", options=all_cols, default=st.session_state.get("show_cols", all_cols))
st.session_state["show_cols"] = show_cols

sort_by = st.selectbox("Sort by", options=["(none)"] + all_cols, index=0)
sort_asc = st.checkbox("Ascending", value=False)

# Sort BEFORE subsetting to avoid KeyError when hiding sort column
base = current
if sort_by != "(none)":
    base = base.sort_values(by=sort_by, ascending=sort_asc, kind="mergesort")
view = base[show_cols] if show_cols else base

if len(current) == 0:
    st.warning("No rows matched your current filters. Click **Reset all filters** below or widen your selections.")

# =============================================================================
# TABS (risk_factors-centric), after Pattern Explorer
# =============================================================================
t_rows, t_asset, t_riskuniq, t_riskuniq_rows = st.tabs(
    ["Rows", "All findings for an asset", "Unique risk_factors (token counts)", "Unique risk_factors (row-wise)"]
)

with t_rows:
    st.dataframe(view, use_container_width=True, height=470)

with t_asset:
    a_col = next((c for c in ["asset_name","asset_id","asset_mrn"] if c in current.columns), None)
    if a_col:
        opts = sorted(current[a_col].dropna().unique().tolist())
        pick = st.selectbox(f"Choose {a_col}", options=["(type to search)"] + opts, index=0)
        if pick != "(type to search)":
            aset = current[current[a_col] == pick]
            st.caption(f"{len(aset):,} rows for {a_col} = {pick!r}")
            st.dataframe(aset[show_cols] if show_cols else aset, use_container_width=True, height=420)
    else:
        st.info("No asset column available.")

with t_riskuniq:
    st.subheader("Unique risk_factors — tokenized counts")
    risk_col_candidates = [c for c in ["risk_factors","risk_factor"] if c in current.columns]
    if not risk_col_candidates:
        st.info("No risk_factors / risk_factor column found.")
    else:
        risk_col = st.selectbox("Column", options=risk_col_candidates, index=0)
        split = st.checkbox("Split values by delimiter (regex)", value=True)
        delim = st.text_input("Delimiter regex", r"[,\|;]")
        do_strip = st.checkbox("Trim whitespace", value=True)
        to_lower = st.checkbox("Lowercase", value=True)

        compute = st.button("Compute counts", key="btn_counts")
        if compute:
            ser = current[risk_col].dropna()
            if split:
                try:
                    parts = ser.str.split(delim, regex=True)
                except Exception:
                    parts = ser.str.split(delim)  # fallback
                tokens = parts.explode()
            else:
                tokens = ser

            if do_strip:
                tokens = tokens.map(lambda x: x.strip() if isinstance(x, str) else x)
            if to_lower:
                tokens = tokens.str.lower()

            tokens = tokens[tokens.notna() & (tokens.astype(str).str.len() > 0)]
            counts = tokens.value_counts(dropna=False).reset_index()
            counts.columns = ["risk_factor", "count"]
            st.dataframe(counts, use_container_width=True, height=420)

            csv_buf = io.StringIO()
            counts.to_csv(csv_buf, index=False)
            st.download_button("Download CSV (risk_factor counts)", csv_buf.getvalue(), file_name="unique_risk_factors_counts.csv", mime="text/csv")
        else:
            st.info("Adjust options, then click **Compute counts**.")

with t_riskuniq_rows:
    st.subheader("Unique risk_factors — row-wise (exact string values)")
    risk_col_candidates = [c for c in ["risk_factors","risk_factor"] if c in current.columns]
    if not risk_col_candidates:
        st.info("No risk_factors / risk_factor column found.")
    else:
        risk_col = st.selectbox("Column ", options=risk_col_candidates, index=0, key="risk_rowwise_col")
        uniq_rows = current.drop_duplicates(subset=[risk_col])
        st.caption(f"Unique rows by {risk_col}: **{len(uniq_rows):,}**")
        st.dataframe(uniq_rows[[risk_col]], use_container_width=True, height=420)
        csv_buf2 = io.StringIO()
        uniq_rows[[risk_col]].to_csv(csv_buf2, index=False)
        st.download_button("Download CSV (unique risk_factors rows)", csv_buf2.getvalue(), file_name="unique_risk_factors_rows.csv", mime="text/csv")

# =============================================================================
# EXPORT & RESET (ENHANCED)
# =============================================================================
st.markdown("---")
st.subheader("Export current view")
fname = st.text_input("File name (no extension)", "findings_filtered")
export_visible_only = st.checkbox("Export only visible columns", value=True, help="If unchecked, exports all columns of the filtered data, respecting current sort.")

# =============================================================================
# EXPORT TO REMEDIATION TOOLS (NEW FEATURE)
# =============================================================================
export_format = st.selectbox("Export format", options=["CSV", "Jira CSV", "ServiceNow CSV"])

to_export = view if export_visible_only else base  # base has full columns; already sorted if requested

if export_format == "Jira CSV":
    # Format for Jira import
    export_df = to_export.copy()
    if "summary" in export_df.columns:
        export_df["Summary"] = export_df["summary"]
    if "asset_name" in export_df.columns:
        export_df["Asset"] = export_df["asset_name"]
    if "cvss_score" in export_df.columns:
        export_df["CVSS"] = export_df["cvss_score"]
    
    # Add Jira-specific columns
    export_df["Issue Type"] = "Vulnerability"
    if "cvss_score" in export_df.columns:
        export_df["Priority"] = export_df["cvss_score"].apply(lambda x: "Highest" if x >= 9.0 else "High" if x >= 7.0 else "Medium" if x >= 4.0 else "Low")
    else:
        export_df["Priority"] = "Medium"
    
    # Select only Jira columns
    jira_cols = ["Summary", "Asset", "CVSS", "Issue Type", "Priority"]
    jira_cols = [c for c in jira_cols if c in export_df.columns]
    export_df = export_df[jira_cols]
    
elif export_format == "ServiceNow CSV":
    # Format for ServiceNow import
    export_df = to_export.copy()
    if "summary" in export_df.columns:
        export_df["Short Description"] = export_df["summary"]
    if "asset_name" in export_df.columns:
        export_df["Configuration Item"] = export_df["asset_name"]
    if "cvss_score" in export_df.columns:
        export_df["Risk Score"] = export_df["cvss_score"]
    
    # Add ServiceNow-specific columns
    export_df["State"] = "New"
    export_df["Assignment Group"] = "Security Team"
    
    # Select only ServiceNow columns
    sn_cols = ["Short Description", "Configuration Item", "Risk Score", "State", "Assignment Group"]
    sn_cols = [c for c in sn_cols if c in export_df.columns]
    export_df = export_df[sn_cols]
else:
    export_df = to_export

buf = io.StringIO()
export_df.to_csv(buf, index=False)
st.download_button("Download CSV", buf.getvalue(), file_name=f"{fname}.csv", mime="text/csv")

if st.button("Reset all filters"):
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    st.rerun()
