class WAFFingerprinter:
    SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "__cfduid"],
            "cookies": ["__cfduid", "cf_clearance"],
            "body": ["cloudflare"],
        },
        "AWS WAF": {
            "headers": ["element-amz-cf-id", "element-amzn-requestid"],
            "cookies": [],
            "body": ["request blocked"],
        },
        "Akamai": {
            "headers": ["element-akamai-transformed"],
            "cookies": ["ak_bmsc"],
            "body": ["akamai"],
        },
        "Imperva": {
            "headers": ["element-cdn", "element-iinfo"],
            "cookies": ["incap_ses_", "visid_incap_"],
            "body": ["incapsula"],
        },
        "F5 BIG-IP": {
            "headers": ["element-wa-info"],
            "cookies": ["f5avr"],
            "body": ["f5 networks"],
        },
        "Sucuri": {
            "headers": ["element-sucuri-id"],
            "cookies": ["sucuri_cloudproxy_uuid"],
            "body": ["sucuri"],
        },
        "Fastly": {
            "headers": ["fastly-debug-digest", "element-served-by"],
            "cookies": [],
            "body": ["fastly"],
        },
        "Azure Front Door": {
            "headers": ["element-azure-ref", "element-ms-request-id"],
            "cookies": [],
            "body": ["azure"],
        },
        "Google Cloud Armor": {
            "headers": [],
            "cookies": [],
            "body": ["google cloud armor"],
        },
        "FortiWeb": {
            "headers": [],
            "cookies": ["fortiwafsid"],
            "body": ["fortiweb"],
        },
    }

    BYPASS = {
        "Cloudflare": ["DNS rebinding", "IPv6 notation"],
        "AWS WAF": ["IMDSv1 downgrade", "alternative metadata IPs"],
        "Imperva": ["double URL encoding", "gopher:// protocol"],
        "Akamai": ["origin IP discovery", "DNS pinning"],
    }

    def fingerprint(self, headers, body, cookies=None):
        cookies = cookies or {}

        headers_lower = {key.lower(): str(value).lower() for key, value in headers.items()}
        body_lower = body.lower()[:10000]
        cookie_keys = [key.lower() for key in cookies]

        results = {}

        for waf, signatures in self.SIGNATURES.items():
            score = 0
            max_score = 0

            for header in signatures["headers"]:
                max_score += 2

                if any(header.lower() in key for key in headers_lower):
                    score += 2

            for cookie in signatures["cookies"]:
                max_score += 2

                if any(cookie.lower() in key for key in cookie_keys):
                    score += 2

            for body_marker in signatures["body"]:
                max_score += 1

                if body_marker in body_lower:
                    score += 1

            if max_score > 0:
                confidence = (score / max_score) * 100

                if confidence >= 20:
                    results[waf] = confidence

        sorted_results = sorted(results.items(), key=lambda item: item[1], reverse=True)

        if sorted_results:
            primary = sorted_results[0][0]

            return {
                "detected": True,
                "primary": primary,
                "confidence": sorted_results[0][1],
                "all_matches": dict(sorted_results[:3]),
                "bypass_suggestions": self.BYPASS.get(primary, []),
            }

        return {
            "detected": False,
            "primary": None,
            "confidence": 0,
        }
