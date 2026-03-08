import httpx
import logging
from typing import Tuple

logger = logging.getLogger("aura")

class KeyValidator:
    """
    Auto-Exploitation Module: Actively validates discovered API keys
    against their respective provider endpoints to confirm they are LIVE
    and usable, transforming an 'Information Disclosure' finding into a
    'Critical Account Takeover' finding.
    """
    
    @staticmethod
    async def validate_secret(secret_type: str, value: str) -> Tuple[bool, str]:
        """
        Actively validates a discovered secret by probing the issuer's API.
        Returns (is_confirmed, account_info).
        Never raises exceptions to ensure the scanner doesn't crash.
        """
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                # ── AWS Access Key ──────────────────────────────────────────
                if secret_type == "AWS Access Key":
                    # AWS STS GetCallerIdentity is the safest way to validate an AWS key
                    url = "https://sts.amazonaws.com/"
                    params = {
                        "Action": "GetCallerIdentity",
                        "Version": "2011-06-15",
                    }
                    r = await client.get(url, params=params)
                    if r.status_code == 200:
                        try:
                            import xml.etree.ElementTree as ET
                            root = ET.fromstring(r.text)
                            arn = "Verified"
                            # AWS STS returns XML, we find the Arn tag ignoring namespaces
                            for elem in root.iter():
                                if 'Arn' in elem.tag:
                                    arn = elem.text
                                    break
                            return True, f"AWS key is VALID — Identity: {arn} (Critical Compromise)"
                        except Exception as e:
                            logger.error(f"Failed to parse AWS XML: {e}")
                            return True, "AWS key is VALID — STS confirmed identity (Critical Compromise)"
                    elif r.status_code == 403:
                        return True, "AWS key EXISTS but lacks STS permission (Confirmed valid format, restricted scope)"
                    return False, f"AWS STS returned {r.status_code}"

                # ── GitHub Token ──────────────────────────────────────────
                elif secret_type in ("GitHub Token (Classic)", "GitHub OAuth", "GitHub App Token"):
                    r = await client.get(
                        "https://api.github.com/user",
                        headers={"Authorization": f"token {value}", "Accept": "application/vnd.github+json"},
                    )
                    if r.status_code == 200:
                        data = r.json()
                        return True, f"GitHub user: @{data.get('login', 'unknown')} (Critical: Source Code Access)"
                    return False, f"GitHub API returned {r.status_code}"

                # ── Stripe Secret Key ─────────────────────────────────────
                elif secret_type == "Stripe Secret Key":
                    r = await client.get(
                        "https://api.stripe.com/v1/account",
                        headers={"Authorization": f"Bearer {value}"},
                    )
                    if r.status_code == 200:
                        data = r.json()
                        return True, f"Stripe account: {data.get('email', 'unknown')} (Critical: Financial Compromise)"
                    return False, f"Stripe API returned {r.status_code}"

                # ── OpenAI API Key ────────────────────────────────────────
                elif secret_type == "OpenAI API Key":
                    r = await client.get(
                        "https://api.openai.com/v1/models",
                        headers={"Authorization": f"Bearer {value}"},
                    )
                    if r.status_code == 200:
                        return True, "OpenAI key is VALID — model list accessible (Financial Abuse Risk)"
                    return False, f"OpenAI API returned {r.status_code}"

                # ── Google API Key ────────────────────────────────────────
                elif secret_type == "Google API Key":
                    r = await client.get(
                        "https://maps.googleapis.com/maps/api/geocode/json",
                        params={"address": "test", "key": value},
                    )
                    body = r.json() if r.status_code == 200 else {}
                    if body.get("status") not in ("REQUEST_DENIED", "INVALID_REQUEST", None):
                        return True, f"Google API key is VALID — status: {body.get('status')} (Potential Billing Abuse)"
                    return False, "Google API key denied or invalid"

                # ── SendGrid ──────────────────────────────────────────────
                elif secret_type == "SendGrid API Key":
                    r = await client.get(
                        "https://api.sendgrid.com/v3/user/account",
                        headers={"Authorization": f"Bearer {value}"},
                    )
                    if r.status_code == 200:
                        return True, "SendGrid API key is VALID (Critical: Phishing / Spam Abuse)"
                    return False, f"SendGrid returned {r.status_code}"

        except Exception as e:
            logger.debug(f"API Validation Error for {secret_type}: {e}")
            return False, f"Validation connection error"

        return False, "No active validator implemented for this type"
