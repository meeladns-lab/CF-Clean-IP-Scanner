from typing import List, Dict, Any

def rank_results(results: List[Dict[str, Any]], top: int = 5) -> List[Dict[str, Any]]:
    """
    Rank by score (lower better), then filter to top N overall_success.
    Only consider entries with overall_success True; others are infinite score.
    If not enough successes, include failures at bottom.
    """
    # Sort by score ascending
    sorted_res = sorted(results, key=lambda r: r.get("score", float("inf")))
    # Filter successes for top
    successes = [r for r in sorted_res if r.get("overall_success")]
    if len(successes) >= top:
        return successes[:top]
    # If not enough successes, fill with failures (sorted at bottom)
    need = top - len(successes)
    failures = [r for r in sorted_res if not r.get("overall_success")]
    return successes + failures[:need]

def rank_with_colo_filter(results: List[Dict[str, Any]], top: int = 5, prefer_colo: List[str] | None = None, exclude_colo: List[str] | None = None) -> List[Dict[str, Any]]:
    filtered = results
    if exclude_colo:
        exclude_set = set(c.upper() for c in exclude_colo)
        filtered = [r for r in filtered if (r.get("colo") or "").upper() not in exclude_set]
    # For prefer, sort boost: prefer colos get score *0.8
    if prefer_colo:
        prefer_set = set(c.upper() for c in prefer_colo)
        for r in filtered:
            colo = (r.get("colo") or "").upper()
            if colo in prefer_set:
                # Boost by 20% lower score
                try:
                    r["_orig_score"] = r.get("score")
                    r["score"] = r.get("score", float("inf")) * 0.8
                except:
                    pass
        # Re-sort after boost, but rank_results will sort again
    ranked = rank_results(filtered, top=top)
    # Restore original scores for display if boosted
    for r in ranked:
        if "_orig_score" in r:
            r["score"] = r["_orig_score"]
            del r["_orig_score"]
    for r in filtered:
        if "_orig_score" in r:
            r["score"] = r["_orig_score"]
            del r["_orig_score"]
    return ranked
