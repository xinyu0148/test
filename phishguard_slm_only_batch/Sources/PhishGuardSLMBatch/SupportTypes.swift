import Foundation

enum LocalAnalysisError: LocalizedError {
    case missingResource(String)
    case invalidTokenizer
    case invalidModelOutput
    case unavailable(String)

    var errorDescription: String? {
        switch self {
        case .missingResource(let name):
            return "\(name) was not found."
        case .invalidTokenizer:
            return "tokenizer.json format is invalid."
        case .invalidModelOutput:
            return "PhishingDetector output is missing probabilities."
        case .unavailable(let message):
            return message
        }
    }
}

enum ModalityType: String, Codable, CaseIterable {
    case text = "text"
    case voice = "voice"
    case video = "video"

    var displayName: String {
        switch self {
        case .text:
            return "Text"
        case .voice:
            return "Voice"
        case .video:
            return "Video"
        }
    }
}

enum DetectionTier: Int, CaseIterable {
    case onDevice = 0
    case localServer = 1
    case cloud = 2

    var apiName: String {
        switch self {
        case .onDevice:
            return "on_device"
        case .localServer:
            return "local_server"
        case .cloud:
            return "cloud_remote"
        }
    }
}

enum RiskLevel: String, Codable {
    case safe = "SAFE"
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"
    case critical = "CRITICAL"

    static func normalizedScore(_ score: Double) -> Double {
        min(10.0, max(0.0, score))
    }

    static func level(for score: Double) -> RiskLevel {
        let normalized = normalizedScore(score)
        if normalized >= 8.5 {
            return .critical
        }
        if normalized >= 7.0 {
            return .high
        }
        if normalized >= 3.0 {
            return .medium
        }
        if normalized >= 1.0 {
            return .low
        }
        return .safe
    }

    static func verdict(for score: Double) -> String {
        switch level(for: score) {
        case .safe, .low:
            return "safe"
        case .medium:
            return "suspicious"
        case .high, .critical:
            return "phishing"
        }
    }

    init(score: Double, verdict: String) {
        self = RiskLevel.level(for: score)
    }
}

struct AnalyzeResponse: Codable, Hashable, Sendable {
    let requestId: String
    let modality: ModalityType
    let inputText: String
    let score: Double
    let level: RiskLevel
    let verdict: String
    let confidence: Double
    let reasoning: String
    let indicators: [String]
    let tierUsed: Int
    let tierName: String
    let latencyMs: Int?
    let wasEscalated: Bool
}

