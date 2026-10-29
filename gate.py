"""GuardedAgents policy gate: risk tiers (Sec. IV-A), provenance (IV-B, Eq. 1),
social context (IV-C, Eq. 2), decision matrix (IV-D, Eq. 3, Table II), consent channel (IV-E)."""
import re

RISK = {  # static manifest tiers
    "describe_scene": 0, "answer": 0,
    "place_private_object": 1, "change_setting": 1,
    "edit_shared_scene": 2, "send_message": 2, "send_friend_request": 2, "share_item": 2,
    "purchase": 3, "share_camera_frame": 3, "share_location": 3, "grant_permission": 3, "delete_asset": 3,
}
T3, T2, T1, T0 = 3, 2, 1, 0
UNATTRIBUTED = T1
CHECKED_ARGS = {"recipient","item","app","permission","asset","object","setting"}  # free text (e.g. message body) not checked

# Table II: M[rho][tau]
M = {
    0: {3: "ALLOW", 1: "ALLOW", 0: "ALLOW"},
    1: {3: "ALLOW", 1: "ALLOW", 0: "CONFIRM"},
    2: {3: "ALLOW", 1: "CONFIRM", 0: "BLOCK"},
    3: {3: "CONFIRM", 1: "BLOCK", 0: "BLOCK"},
}

# Lightweight rule-based intent parser I(u), independent of the LLM.
INTENT_RULES = [
    ("purchase", r"\b(buy|purchase)\b"),
    ("share_location", r"\blocation\b"),
    ("share_camera_frame", r"\b(snapshot|photo|picture)\b"),
    ("send_friend_request", r"\bfriend request\b"),
    ("send_message", r"\bmessage\b"),
    ("edit_shared_scene", r"\b(add|move|remove)\b.*\b(shared|whiteboard|board|table)\b"),
    ("place_private_object", r"\b(place|pin)\b"),
    ("change_setting", r"\b(turn on|turn off|dark mode|volume|lower|raise)\b"),
    ("delete_asset", r"\bdelete\b"),
    ("grant_permission", r"\bpermission\b"),
    ("share_item", r"\bshare\b.*\b(item|link)\b"),
    ("describe_scene", r"\b(what|read|describe|say|said|who|summari[sz]e|repeat)\b"),
    ("answer", r"\b(what|price|who|summari[sz]e)\b"),
]

def intents(u):
    u = u.lower()
    return {tool for tool, pat in INTENT_RULES if re.search(pat, u)}

def _norm(s): return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", "", re.sub(r"[_\-]", " ", str(s).lower()))).strip()

def args_first_party(args, u, sel):
    """Every argument value must originate from T3 (utterance) or T2 (gaze-selected object)."""
    u_n = _norm(u); sel_n = _norm(sel) if sel else ""
    for k, v in args.items():
        if k not in CHECKED_ARGS: continue  # free-text content is not provenance-checked
        v_n = _norm(v)
        if not v_n: continue
        if k == "permission" and v_n in u_n: continue
        if v_n in u_n or (sel_n and (v_n == sel_n or v_n in sel_n or sel_n in v_n)):
            continue
        return False
    return True

def tau(action, scen):
    tool, args = action
    u, sel = scen["utter"], scen.get("sel")
    if tool in intents(u) and args_first_party(args, u, sel):
        return T3
    others = [o[1] for o in scen["obs"]]
    return min(others) if others else UNATTRIBUTED

def rho(action, ctx):
    r = RISK.get(action[0], 3)  # unknown tool -> fail closed as R3
    exposed = ctx is None or ctx.get("pres") or ctx.get("pub") or ctx.get("rec")
    return min(3, r + (1 if (r >= 1 and exposed) else 0))

def decide(action, scen):
    return M[rho(action, scen.get("ctx"))][tau(action, scen)]

# ---- consent channel (IV-E), simulated input routing ----
def consent(prompt_layer, event_origin, user_choice):
    """prompt_layer: 'in_scene' (dialog drawn in app/scene layer, as in generic agent guards)
                     'system'   (reserved compositor layer, GuardedAgents)
       event_origin: 'system_input' (real gaze+pinch routed by the system) or
                     'app' (app-synthesized, clickjacked, or raycast-redirected event)
       user_choice: what the real user would choose ('approve'/'deny'/None if attacker acts)."""
    if prompt_layer == "system":
        if event_origin != "system_input":
            return "deny"  # app events cannot reach the reserved layer; timeout -> deny
        return user_choice or "deny"
    # in-scene dialog: any pointer event that hits the button counts
    if event_origin == "app":
        return "approve"
    return user_choice or "deny"
