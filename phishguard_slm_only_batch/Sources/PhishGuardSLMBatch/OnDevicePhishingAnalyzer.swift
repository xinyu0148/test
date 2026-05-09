import Foundation

struct OnDevicePhishingResult {
    let prediction: String
    let confidence: Double
    let isPhishing: Bool
    let phishingRisk: Double
    let allProbabilities: [String: Double]
}

final class OnDevicePhishingAnalyzer {
    private let detector: PhishingDetectorRunner

    init(detector: PhishingDetectorRunner? = nil) throws {
        if let detector {
            self.detector = detector
        } else {
            self.detector = try PhishingDetectorRunner()
        }
        print("[OnDevicePhishingAnalyzer] on-device analyzer initialized successfully")
    }

    func analyze(text: String, modality: ModalityType, startedAt start: Date = Date()) throws -> AnalyzeResponse {
        let result = try detector.detect(text)
        let latencyMs = max(1, Int(Date().timeIntervalSince(start) * 1000))
        return result.asAnalyzeResponse(
            requestId: UUID().uuidString,
            inputText: text,
            modality: modality,
            latencyMs: latencyMs
        )
    }
}

private extension OnDevicePhishingResult {
    func asAnalyzeResponse(requestId: String, inputText: String, modality: ModalityType, latencyMs: Int) -> AnalyzeResponse {
        let contentSignals = ContentRiskSignals(text: inputText)
        let slmScore = discreteSLMScore
        let ruleScore = contentSignals.ruleScore
        let score = min(10.0, max(0.0, slmScore + ruleScore))
        let verdict = mappedVerdict(score: score)
        let indicators = mappedIndicators(contentSignals: contentSignals, slmScore: slmScore, finalScore: score)
        let rationale = mappedRationale(
            verdict: verdict,
            score: score,
            slmScore: slmScore,
            ruleScore: ruleScore,
            contentSignals: contentSignals
        )

        return AnalyzeResponse(
            requestId: requestId,
            modality: modality,
            inputText: inputText,
            score: score,
            level: RiskLevel(score: score, verdict: verdict),
            verdict: verdict,
            confidence: confidence,
            reasoning: rationale,
            indicators: indicators,
            tierUsed: DetectionTier.onDevice.rawValue,
            tierName: "on_device",
            latencyMs: latencyMs,
            wasEscalated: false
        )
    }

    func mappedVerdict(score: Double) -> String {
        RiskLevel.verdict(for: score)
    }

    func mappedRationale(
        verdict: String,
        score: Double,
        slmScore: Double,
        ruleScore: Double,
        contentSignals: ContentRiskSignals
    ) -> String {
        let percent = Int((phishingRisk * 100).rounded())
        var parts = [
            "Local SLM semantic risk contributed \(String(format: "%.2f", slmScore)) / 3.00 (\(percent)% phishing probability).",
            "Rule/context signals adjusted the score by \(String(format: "%.2f", ruleScore))."
        ]
        if !contentSignals.triggeredLabels.isEmpty {
            parts.append("Triggered signals: \(contentSignals.triggeredLabels.joined(separator: ", ")).")
        }
        switch verdict {
        case "phishing":
            parts.append("Final fused score indicates phishing risk.")
        case "suspicious":
            parts.append("Final fused score indicates suspicious content.")
        default:
            parts.append("Final fused score indicates low risk.")
        }
        parts.append("Final score: \(String(format: "%.2f", score)) / 10.00.")
        return parts.joined(separator: " ")
    }

    func mappedIndicators(contentSignals: ContentRiskSignals, slmScore: Double, finalScore: Double) -> [String] {
        let probabilityIndicators = allProbabilities
            .filter { $0.value >= 0.2 }
            .sorted { $0.value > $1.value }
            .map { label, probability in
                "\(label): \(Int((probability * 100).rounded()))%"
            }

        return [
            "slm semantic score: \(String(format: "%.2f", slmScore))/3.00",
            "fused local score: \(String(format: "%.2f", finalScore))/10.00"
        ] + contentSignals.indicators + probabilityIndicators
    }

    var discreteSLMScore: Double {
        min(3.0, max(0.0, phishingRisk * 3.0))
    }
}

private struct ContentRiskSignals {
    let hasSuspiciousURLDomain: Bool
    let requestsSensitiveInfo: Bool
    let hasUrgencyThreat: Bool

    init(text: String) {
        let lowercased = text.lowercased()
        let suspiciousURLTerms = [
            "login", "signin", "verify", "secure", "update", "reset", "wallet",
            "bank", "payment", "suspended", "suspend", "confirm"
        ]
        let sensitiveTerms = [
            "password", "passcode", "verification code", "verify code", "otp", "one-time code",
            "bank account", "account number", "card number", "credit card", "debit card",
            "cvv", "full name", "date of birth", "dob", "social security"
        ]
        let requestVerbs = ["send", "provide", "confirm", "share", "enter", "reply with", "submit", "verify"]
        let urgencyTerms = [
            "urgent", "verify now", "immediately", "within 10 minutes", "suspended", "permanent suspension",
            "loss of funds", "final warning", "expires today", "act now", "asap"
        ]

        let containsLink = lowercased.contains("http://") || lowercased.contains("https://") || lowercased.contains("www.")
        let containsSuspiciousTerm = suspiciousURLTerms.contains { lowercased.contains($0) }
        hasSuspiciousURLDomain = containsLink && containsSuspiciousTerm

        let containsSensitiveTerm = sensitiveTerms.contains { lowercased.contains($0) }
        let containsRequestVerb = requestVerbs.contains { lowercased.contains($0) }
        requestsSensitiveInfo = containsSensitiveTerm && containsRequestVerb

        hasUrgencyThreat = urgencyTerms.contains { lowercased.contains($0) }
    }

    var ruleScore: Double {
        var total = 0.0
        if hasSuspiciousURLDomain {
            total += 2.0
        }
        if requestsSensitiveInfo {
            total += 2.0
        }
        if hasUrgencyThreat {
            total += 1.0
        }
        return min(total, 5.0)
    }

    var triggeredLabels: [String] {
        var labels: [String] = []
        if hasSuspiciousURLDomain {
            labels.append("suspicious URL/domain")
        }
        if requestsSensitiveInfo {
            labels.append("sensitive information request")
        }
        if hasUrgencyThreat {
            labels.append("urgency/threat language")
        }
        return labels
    }

    var indicators: [String] {
        var values: [String] = []
        if hasSuspiciousURLDomain {
            values.append("suspicious url/domain signal")
        }
        if requestsSensitiveInfo {
            values.append("sensitive information request signal")
        }
        if hasUrgencyThreat {
            values.append("urgency/threat signal")
        }
        return values
    }
}
