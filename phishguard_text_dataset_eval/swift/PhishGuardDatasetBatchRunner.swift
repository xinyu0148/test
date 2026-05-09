import Foundation

struct DatasetTextSample: Decodable {
    let id: String
    let source_group: String
    let source_file: String
    let row_number: Int
    let actual_label: String
    let analysis_text: String
}

struct DatasetLocalResult: Encodable {
    let id: String
    let source_group: String
    let actual_label: String
    let score: Double
    let level: String
    let verdict: String
    let confidence: Double
    let reasoning: String
    let indicators: [String]
    let latency_ms: Int?
    let local_decision: String
}

enum DatasetBatchRunner {
    static func runFromBundle(
        resourceName: String = "phishguard_text_dataset",
        resourceExtension: String = "jsonl"
    ) async throws -> URL {
        guard let inputURL = Bundle.main.url(forResource: resourceName, withExtension: resourceExtension) else {
            throw NSError(
                domain: "DatasetBatchRunner",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "\(resourceName).\(resourceExtension) was not found in the app bundle."]
            )
        }

        let samples = try loadSamples(from: inputURL)
        let results = try await analyze(samples)
        return try writeResults(results)
    }

    static func analyze(_ samples: [DatasetTextSample]) async throws -> [DatasetLocalResult] {
        var results: [DatasetLocalResult] = []

        for sample in samples {
            let response = try await LocalSLMService.shared.analyze(
                text: sample.analysis_text,
                modality: .text
            )
            let score = RiskLevel.normalizedScore(response.score)
            let decision = localDecision(score: score)

            results.append(DatasetLocalResult(
                id: sample.id,
                source_group: sample.source_group,
                actual_label: sample.actual_label,
                score: score,
                level: RiskLevel.level(for: score).rawValue,
                verdict: RiskLevel.verdict(for: score),
                confidence: response.confidence,
                reasoning: response.reasoning,
                indicators: response.indicators,
                latency_ms: response.latencyMs,
                local_decision: decision
            ))
        }

        return results
    }

    private static func localDecision(score: Double) -> String {
        if score < 3.0 {
            return "local_safe"
        }
        if score <= 6.5 {
            return "needs_server"
        }
        return "local_phishing"
    }

    private static func loadSamples(from url: URL) throws -> [DatasetTextSample] {
        let text = try String(contentsOf: url, encoding: .utf8)
        let decoder = JSONDecoder()
        return try text
            .split(separator: "\n")
            .map { Data($0.utf8) }
            .map { try decoder.decode(DatasetTextSample.self, from: $0) }
    }

    private static func writeResults(_ results: [DatasetLocalResult]) throws -> URL {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        let lines = try results.map { result -> String in
            let data = try encoder.encode(result)
            return String(decoding: data, as: UTF8.self)
        }

        let documentsURL = try FileManager.default.url(
            for: .documentDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let outputURL = documentsURL.appendingPathComponent("phishguard_local_results.jsonl")
        try lines.joined(separator: "\n").write(to: outputURL, atomically: true, encoding: .utf8)
        print("[DatasetBatchRunner] Wrote \(results.count) results to \(outputURL.path)")
        return outputURL
    }
}
