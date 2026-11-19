"""L1a Signature rules: transparent, explainable patterns for known injection techniques.

Each rule targets one technique and carries a plain-language explanation shown in
the dashboard when it fires. Rules run on the *normalized* text (``normalizer.py``):
encodings are decoded, look-alike characters mapped, slang expanded and typos in
key words repaired, so "reveal ur sys promt" is checked as "reveal your system
prompt". Accents are also folded so "révélez" and "revelez" match alike.

Some rules only make sense for *documents* the assistant retrieves (emails,
files, web pages): a sentence addressed to "AI assistant:" is normal in your own
chat but a strong sign of indirect injection inside an email.

Rules are fast and auditable but brittle against genuinely new wording, which is
why the ML classifier and similarity search run alongside them.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .normalizer import normalize

ANY = ("input", "document")
DOCS = ("document",)

# Shared vocabulary -------------------------------------------------------------------------
ASK = (
    r"(?:reveal|print|show|disclose|leak|output|repeat|give|tell|share|display|dump|expose|spell out|"
    r"write out|write down|provide|paste|recite|translate|summari[sz]e|list|send|read out|type out|"
    r"what(?:'s| is| are| was| were))"
)
SECRET = (
    r"(?:secret(?!\s+(?:santa|recipe|sauce|garden|menu|party|to|of))|password(?!\s+(?:policy|reset|"
    r"manager|rules|requirements|strength))|passcode|canary(?: token)?|api[ -]?key|credentials?|"
    r"access token|verification token|confidential (?:value|data|information|configuration))"
)
PROMPT = (
    r"(?:(?:your|the) system (?:prompt|message|instructions)|"
    r"(?:your|the) (?:initial|original|hidden|internal|secret|developer|real|full|exact|first) "
    r"(?:prompt|instructions|message|configuration|rules|directives)|"
    r"(?:the )?(?:instructions|prompt|rules) you (?:received|were given|got|follow)|"
    r"(?:your|the) (?:instructions|configuration|directives|guidelines|rules) (?:you were given|above)|"
    r"your (?:instructions|configuration|directives)|"
    r"(?:the )?(?:text|words|message|everything|anything) (?:above|before this)|what you were told)"
)
AI = (
    r"(?:ai|a\.i\.|assistants?|ai assistants?|ai agents?|agents?|llms?|large language models?|"
    r"language models?|chatbots?|bots?|gpt|claude|copilot|models?)"
)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: str
    explanation: str
    stages: tuple[str, ...] = ANY
    # Skip a match preceded by a negation: "never share your password" is advice.
    negatable: bool = False


NEGATION = re.compile(r"\b(?:never|don'?t|do not|must not|should not|shouldn'?t|not|no one|nobody)\b")


RULES: tuple[Rule, ...] = (
    # --- instruction override -------------------------------------------------------------
    Rule(
        "override-previous",
        "instruction override",
        r"\b(?:ignore|disregard|forget|override|bypass|skip|drop|abandon|discard|neglect|set aside|"
        r"stop following|do not follow|don't follow)\b[^.\n]{0,30}?\b(?:previous|prior|above|earlier|"
        r"preceding|all|any|your|system|original|initial|existing|safety|developer)\b[^.\n]{0,20}?"
        r"\b(?:instructions?|rules|guidelines|directions|directives|prompts?|guidance|constraints|"
        r"restrictions|polic(?:y|ies)|programming|training|context)\b",
        "Tries to cancel the assistant's original instructions so new ones take over.",
    ),
    Rule(
        "instructions-void",
        "instruction override",
        r"\b(?:instructions|directives|rules|restrictions|guidelines)\s+(?:are|have been|were)\s+"
        r"(?:cancell?ed|void|revoked|lifted|disabled|suspended|updated|replaced|no longer valid)\b|"
        r"\bforget (?:everything|all of that|all that)\b|\bstart (?:over|fresh) with new instructions\b",
        "Claims the original rules no longer apply.",
    ),
    Rule(
        "new-instructions",
        "instruction override",
        r"\b(?:new|updated|real|true|actual|revised) (?:instructions?|rules|directives?|orders|"
        r"system prompt)\s*(?:are\s*)?[:：]|\bfrom now on,? (?:you|your|ignore|only|always|respond)\b",
        "Announces replacement instructions, a classic way to hijack the assistant.",
    ),
    # --- data and prompt leaking ----------------------------------------------------------
    Rule(
        "reveal-secret",
        "data leak",
        rf"\b{ASK}\b[^.\n]{{0,35}}?\b(?:the|your|this|that|any|all|me the|us the)\s+(?:\w+\s+)?{SECRET}\b|"
        rf"\b{SECRET}\b[^.\n]{{0,15}}\b(?:is|=)\s*\?",
        "Asks the assistant to disclose protected data (secrets, passwords, keys, tokens).",
        negatable=True,
    ),
    Rule(
        "prompt-extraction",
        "prompt leaking",
        rf"\b{ASK}\b[^.\n]{{0,30}}?\b{PROMPT}|\brepeat (?:everything|all|the (?:text|words))\b|"
        r"\bwhat (?:were|are) you (?:told|instructed|programmed)\b|\bverbatim\b[^.\n]{0,40}\b(?:prompt|instructions)\b",
        "Tries to make the assistant recite its hidden system prompt or instructions.",
        negatable=True,
    ),
    # --- persona and jailbreak ------------------------------------------------------------
    Rule(
        "jailbreak-persona",
        "role-play / jailbreak",
        r"\b(?:unrestricted|uncensored|unfiltered|unaligned|jailbroken|evil|amoral)\s+(?:assistant|ai|bot|"
        r"model|mode|version|persona|character)\b|\b(?:jailbreak|dan|god)\s+mode\b|"
        r"\b(?:enable|enter|activate|switch (?:on|to)|turn on|you are (?:now )?in|now in)\s+(?:the )?"
        r"(?:developer|debug|admin|sudo|maintenance)\s+mode\b|\b(?:developer|debug|sudo)\s+mode\s*[:(]|"
        r"\bdo anything now\b|\byou are (?:now )?(?:dan|stan|dude|aim)\b|"
        r"\b(?:pretend|act|imagine|roleplay|role-play|behave)\b[^.\n]{0,60}\b(?:no|without|zero)\s+"
        r"(?:rules|restrictions|limits|filters|guidelines|morals|ethics)\b",
        "Asks the assistant to become a persona without its safety rules.",
    ),
    Rule(
        "emotional-manipulation",
        "role-play / jailbreak",
        r"\bgrand(?:ma|mother|pa|father)\b[^.\n]{0,60}\b(?:used to|would)\b[^.\n]{0,30}\b(?:read|tell|recite|"
        r"say)\b|\b(?:i will (?:die|lose my job|be fired)|life or death|people will (?:die|get hurt))\b",
        "Uses emotional pressure (the 'grandma' trick, fake emergencies) to override the rules.",
    ),
    Rule(
        "refusal-suppression",
        "refusal suppression",
        r"\b(?:never|do not|don't|must not|cannot|can't|won't)\s+(?:refuse|decline|say (?:no|that you can'?t|"
        r"you can'?t|sorry)|apologi[sz]e|mention (?:your )?(?:rules|policy|guidelines))\b|"
        r"\byou (?:must|have to|are required to|will) (?:always )?(?:answer|comply|obey)\b|"
        r"\bwithout (?:any )?(?:warnings?|disclaimers?|refus\w+|filters?|censorship)\b|\bno matter what\b",
        "Forbids the assistant from refusing, which removes its last line of defense.",
    ),
    Rule(
        "prefix-injection",
        "refusal suppression",
        r"\b(?:start|begin) your (?:reply|answer|response|message|output) with\b[^.\n]{0,10}"
        r"(?:[\"'“]|sure|of course|absolutely|certainly|here is|yes)",
        "Forces the reply to begin with 'Sure, here is…' so the model continues the attacker's script.",
    ),
    # --- context confusion ----------------------------------------------------------------
    Rule(
        "fake-system-tag",
        "context confusion",
        r"<\|(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\|>|\[/?(?:system|inst|sys)\]|"
        r"<<\s*sys\s*>>|#{2,}\s*(?:system|override|admin|instructions?)\b|-{3,}\s*system (?:message|prompt)|"
        r"</?(?:system|instructions?|admin)>|\"role\"\s*:\s*\"(?:system|developer)\"|"
        r"(?:^|\n)\s*(?:system|admin|developer|root)\s*(?:message|prompt|override)?\s*[:>]",
        "Imitates the special markers that separate system and user messages.",
    ),
    Rule(
        "context-termination",
        "context confusion",
        r"\bend of (?:user|the user|input|prompt|document|email|message|conversation|context|data)\b|"
        r"(?:-{3,}|={3,}|\*{3,})\s*(?:system|new|admin|begin|end)\b|</(?:user|document|email|context|data)>|"
        r"\bbegin (?:system|admin|new) (?:prompt|instructions)\b",
        "Pretends the user's text has ended so what follows looks like official instructions.",
    ),
    Rule(
        "fake-dialogue",
        "context confusion",
        r"(?:^|\n)\s*(?:user|human|q)\s*:[^\n]{0,200}\n\s*(?:assistant|ai|bot|a)\s*:",
        "Fakes an earlier conversation where the assistant already agreed (few-shot priming).",
    ),
    # --- obfuscation helpers --------------------------------------------------------------
    Rule(
        "decode-and-follow",
        "obfuscation",
        r"\b(?:decode|decipher|decrypt|unscramble|reverse|rot-?13|base64)\b[^\n]{0,50}?\b(?:and|then)\b[^\n]{0,20}?"
        r"\b(?:follow|execute|obey|do|run|comply|carry out|perform|act on)\b|"
        r"\bfollow the (?:decoded|hidden|encoded|reversed) (?:instructions?|text|message)\b",
        "Asks the assistant to decode hidden text and act on it.",
    ),
    Rule(
        "payload-splitting",
        "payload splitting",
        r"\b[a-z]\w{0,9}\s*=\s*[\"'“][^\"'”\n]{1,80}[\"'”][\s\S]{0,200}?\b[a-z]\w{0,9}\s*\+\s*[a-z]\w{0,9}\b|"
        r"\b(?:combine|concatenate|join|merge)\b[^.\n]{0,20}\b(?:the )?(?:strings|parts|variables|pieces|"
        r"fragments)\b[^.\n]{0,40}\b(?:and|then)\b[^.\n]{0,20}\b(?:follow|execute|do|run|answer)\b|"
        r"\b(?:do|execute|run|perform|carry out|follow|combine|concatenate)\s+[a-z]\w{0,9}\s*\+\s*[a-z]\w{0,9}\b|"
        r"\b[a-z]\w{0,9}\s*\+\s*[a-z]\w{0,9}\b[^.\n]{0,20}\b(?:and )?(?:do it|execute|run it|follow it)\b",
        "Splits a forbidden request into pieces for the model to reassemble.",
    ),
    Rule(
        "output-evasion",
        "data leak",
        r"\b(?:write|spell|say|output|give|encode|answer|reply|print)\b[^.\n]{0,40}\b(?:backwards|in reverse|"
        r"reversed|in base64|as base64|base64[- ]encoded|letter by letter|with (?:spaces|dashes|dots) between)\b|"
        r"\bso (?:that )?(?:the |no )?(?:filters?|guard|moderation|monitor)\w* (?:does not|doesn't|won't|"
        r"will not|cannot|can't)? ?(?:notices?|catch|see|detect)\b|\b(?:evade|bypass|avoid|dodge|trick) "
        r"(?:the |any )?(?:filters?|detection|moderation|guard)\b",
        "Asks for the answer in a disguised form so output filters miss the leak.",
    ),
    # --- exfiltration ---------------------------------------------------------------------
    Rule(
        "exfiltrate-email",
        "data exfiltration",
        r"\b(?:send|forward|email|mail|transmit|cc|bcc|post|upload|leak)\b[^.\n]{0,50}?\b(?:secret|password|"
        r"credentials?|canary|api key|token|conversation|chat history|inbox|all (?:the )?(?:emails|messages|"
        r"data|files)|everything|user'?s (?:data|emails|inbox))\b[^.\n]{0,40}?\b(?:to|a|an|para)\s+[\w.+-]+@",
        "Asks the assistant to send protected data to an email address.",
    ),
    Rule(
        "exfiltrate-image",
        "data exfiltration",
        r"!\[[^\]]*\]\(https?://|\b(?:render|embed|include|insert|display|load)\b[^.\n]{0,30}?"
        r"\b(?:image|pixel|markdown|img)\b[^.\n]{0,80}?https?://|https?://[^\s)]*[?&][a-z_]*=\s*"
        r"(?:\{|\[|<)?(?:secret|password|data|token|key)\b",
        "Uses an image or link URL to smuggle data out when the reply is displayed.",
    ),
    # --- multilingual ---------------------------------------------------------------------
    Rule(
        "multilingual-override",
        "multilingual",
        r"\b(?:ignor(?:ez|er|a|ar|iere|ieren|e)|oubli(?:e|ez)|olvid(?:a|e)|vergiss|dimentica|esqueca)\b"
        r"[^.\n]{0,25}\b(?:consignes|regles|instrucciones|reglas|anweisungen|regeln|istruzioni|regole|"
        r"instrucoes|regras)\b|"
        r"\b(?:ignor(?:ez|er|ar|iere|ieren)|oubli(?:e|ez)|olvid(?:a|e)|vergiss|dimentica|esqueca)\b"
        r"[^.\n]{0,25}\binstructions?\b",
        "Instruction override written in French, Spanish, German, Italian or Portuguese.",
    ),
    Rule(
        "multilingual-leak",
        "multilingual",
        r"\b(?:revel\w*|rivel\w*|verrat\w*|affich\w*|montr\w*|muestr\w*|mostr\w*|zeig\w*|donne\w*|dame|dimmi|"
        r"gib|envo\w*|envi\w*|invia\w*|send\w*)\b[^.\n]{0,25}\b(?:secret|secreto|geheimnis|segreto|segredo|"
        r"mot de passe|contrasena|passwort|senha|prompt (?:systeme|del sistema|di sistema|do sistema)|"
        r"systemanweisung|systemprompt)\b",
        "Asks for the secret or the system prompt in another language.",
    ),
    # --- indirect injection (documents only) ----------------------------------------------
    Rule(
        "addressed-to-ai",
        "indirect injection",
        rf"(?:^|[\n.!?>]\s*|<!--\s*|\(\s*|\*\s*)(?:hey |hi |dear |attention,? |p\.?s\.? |"
        rf"(?:a )?(?:note|message|instructions?|reminder) (?:for|to) (?:the |any |all )?)?(?:the )?{AI}\b"
        rf"(?:\s+(?:reading|processing|summari[sz]ing|parsing) this)?\s*[,:!]\s*\S|"
        rf"\bif you(?: are|'re| re|re) an? (?:ai|llm|language model|assistant|bot|chatbot|agent)\b|"
        rf"\b(?:any|all) {AI} (?:reading|processing|summari[sz]ing|parsing) this\b|"
        rf"\binstructions? for {AI}\b|\b(?:for|to) (?:the |any |all )?{AI}\s*[:,]\s*\S",
        "Text inside a document that speaks directly to the AI: documents should contain data, "
        "not instructions for the assistant.",
        DOCS,
    ),
    Rule(
        "dictated-reply",
        "indirect injection",
        r"\bwhen (?:you|the ai|the assistant|an ai) (?:summari[sz]e|read|process|parse|see|analy[sz]e)s? this\b|"
        r"\b(?:reply|respond|answer|say|output)\s+only\s+(?:with\s*:?\s*)?[\"'“]",
        "A document tells the assistant how to process it or what exactly to answer.",
        DOCS,
    ),
)

# A narrow request-safety rule, separate from prompt-injection detection. It
# blocks direct requests to steal or collect credentials while allowing
# defensive questions about preventing credential theft.
SAFETY_RULES: tuple[Rule, ...] = (
    Rule(
        "credential-theft",
        "safety (not injection)",
        r"\b(?:how\s+(?:do|can|could)\s+(?:i|we|someone)\s+|ways?\s+to\s+|methods?\s+to\s+|"
        r"teach\s+me\s+to\s+|show\s+me\s+how\s+to\s+|help\s+me\s+|i want to\s+|i need to\s+)"
        r"(?:steal|phish|harvest|capture|collect|exfiltrate)\s+"
        r"(?:(?:someone|users?|people|victims?)['’]s?\s+)?"
        r"(?:login\s+)?(?:passwords?|credentials?|login details|authentication tokens|session cookies)\b",
        "Direct request to steal credentials (a harmful request, not a prompt injection).",
    ),
)


@dataclass(frozen=True)
class RuleMatch:
    rule: Rule
    excerpt: str


def _fold(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn")


def match_rules(text: str, exact_rules: tuple[str, ...] = (), stage: str = "input") -> list[RuleMatch]:
    normalized = normalize(text)
    folded = _fold(normalized)
    matches: list[RuleMatch] = []
    for signature in exact_rules:
        if signature and signature in normalized:
            matches.append(
                RuleMatch(
                    Rule(
                        "hardened-exact",
                        "learned signature",
                        re.escape(signature),
                        "Matches an attack discovered by the fuzzer in a previous hardening round.",
                    ),
                    signature[:80],
                )
            )
            break
    for rule in RULES + SAFETY_RULES:
        if stage not in rule.stages:
            continue
        for found in re.finditer(rule.pattern, folded):
            before = folded[max(0, found.start() - 25) : found.start() + 1]
            if rule.negatable and NEGATION.search(before):
                continue
            matches.append(RuleMatch(rule, found.group().strip()[:80]))
            break
    return matches


def classify(text: str, exact_rules: tuple[str, ...] = (), stage: str = "input") -> tuple[bool, float, str]:
    """Backwards-compatible summary: (blocked, score, reason)."""
    matches = match_rules(text, exact_rules, stage)
    if not matches:
        return False, 0.0, "no signature rule matched"
    first = matches[0].rule
    if first.id == "credential-theft":
        return True, 0.99, "matched safety rule: direct credential theft request"
    if first.id == "hardened-exact":
        return True, 1.0, "matched hardened exact-text rule"
    return True, 0.95, f"matched rule '{first.id}' ({first.category})"
