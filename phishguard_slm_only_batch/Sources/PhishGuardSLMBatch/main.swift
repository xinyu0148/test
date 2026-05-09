import Foundation

struct DatasetTextSample: Decodable {
    let id: String
    let sourceGroup: String
    let sourceFile: String
    let rowNumber: Int
    let actualLabel: String
    let analysisText: String

    enum CodingKeys: String, CodingKey {
        case id
        case sourceGroup = "source_group"
        case sourceFile = "source_file"
        case rowNumber = "row_number"
        case actualLabel = "actual_label"
        case analysisText = "analysis_text"
    }
}

struct DatasetLocalResult: Encodable {
    let id: String
    let sourceGroup: String
    let sourceFile: String
    let rowNumber: Int
    let actualLabel: String
    let score: Double
    let level: String
    let verdict: String
    let confidence: Double
    let reasoning: String
    let indicators: [String]
    let latencyMs: Int?
    let localDecision: String

    enum CodingKeys: String, CodingKey {
        case id
        case sourceGroup = "source_group"
        case sourceFile = "source_file"
        case rowNumber = "row_number"
        case actualLabel = "actual_label"
        case score
        case level
        case verdict
        case confidence
        case reasoning
        case indicators
        case latencyMs = "latency_ms"
        case localDecision = "local_decision"
    }
}

struct Arguments {
    let datasetPath: String
    let modelPath: String
    let tokenizerPath: String
    let outputPath: String
    let limit: Int?
}

enum BatchRunnerError: LocalizedError {
    case missingArgument(String)
    case invalidArguments(String)

    var errorDescription: String? {
        switch self {
        case .missingArgument(let name):
            return "Missing required argument: \(name)"
        case .invalidArguments(let message):
            return message
        }
    }
}

func parseArguments(_ raw: [String]) throws -> Arguments {
    var values: [String: String] = [:]
    var index = 1
    while index < raw.count {
        let key = raw[index]
        guard key.hasPrefix("--") else {
            throw BatchRunnerError.invalidArguments("Unexpected argument: \(key)")
        }
        guard index + 1 < raw.count else {
            throw BatchRunnerError.invalidArguments("Missing value for \(key)")
        }
        values[key] = raw[index + 1]
        index += 2
    }

    guard let datasetPath = values["--dataset"] else {
        throw BatchRunnerError.missingArgument("--dataset")
    }
    guard let modelPath = values["--model"] else {
        throw BatchRunnerError.missingArgument("--model")
    }
    guard let tokenizerPath = values["--tokenizer"] else {
        throw BatchRunnerError.missingArgument("--tokenizer")
    }

    let outputPath = values["--output"] ?? "output/phishguard_local_results.jsonl"
    let limit = values["--limit"].flatMap(Int.init)
    return Arguments(
        datasetPath: datasetPath,
        modelPath: modelPath,
        tokenizerPath: tokenizerPath,
        outputPath: outputPath,
        limit: limit
    )
}

func loadSamples(from path: String, limit: Int?) throws -> [DatasetTextSample] {
    let url = URL(fileURLWithPath: path)
    let text = try String(contentsOf: url, encoding: .utf8)
    let decoder = JSONDecoder()
    var samples: [DatasetTextSample] = []

    for line in text.split(separator: "\n") {
        let data = Data(line.utf8)
        samples.append(try decoder.decode(DatasetTextSample.self, from: data))
        if let limit, samples.count >= limit {
            break
        }
    }
    return samples
}

func localDecision(score: Double) -> String {
    if score < 3.0 {
        return "local_safe"
    }
    if score <= 6.5 {
        return "needs_server"
    }
    return "local_phishing"
}

func writeJSONL(_ results: [DatasetLocalResult], to path: String) throws {
    let outputURL = URL(fileURLWithPath: path)
    let outputDir = outputURL.deletingLastPathComponent()
    try FileManager.default.createDirectory(at: outputDir, withIntermediateDirectories: true)

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    let lines = try results.map { result -> String in
        let data = try encoder.encode(result)
        return String(decoding: data, as: UTF8.self)
    }
    try lines.joined(separator: "\n").write(to: outputURL, atomically: true, encoding: .utf8)
}

func run() throws {
    let args = try parseArguments(CommandLine.arguments)
    let samples = try loadSamples(from: args.datasetPath, limit: args.limit)

    let modelURL = URL(fileURLWithPath: args.modelPath)
    let tokenizerURL = URL(fileURLWithPath: args.tokenizerPath)
    let detector = try PhishingDetectorRunner(modelURL: modelURL, tokenizerURL: tokenizerURL)
    let analyzer = try OnDevicePhishingAnalyzer(detector: detector)

    var results: [DatasetLocalResult] = []
    results.reserveCapacity(samples.count)

    for (index, sample) in samples.enumerated() {
        let response = try analyzer.analyze(text: sample.analysisText, modality: .text)
        let score = RiskLevel.normalizedScore(response.score)
        results.append(DatasetLocalResult(
            id: sample.id,
            sourceGroup: sample.sourceGroup,
            sourceFile: sample.sourceFile,
            rowNumber: sample.rowNumber,
            actualLabel: sample.actualLabel,
            score: score,
            level: RiskLevel.level(for: score).rawValue,
            verdict: RiskLevel.verdict(for: score),
            confidence: response.confidence,
            reasoning: response.reasoning,
            indicators: response.indicators,
            latencyMs: response.latencyMs,
            localDecision: localDecision(score: score)
        ))

        if (index + 1) % 100 == 0 || index + 1 == samples.count {
            print("[SLM Batch] Processed \(index + 1)/\(samples.count)")
        }
    }

    try writeJSONL(results, to: args.outputPath)
    print("[SLM Batch] Wrote \(results.count) results to \(args.outputPath)")
}

do {
    try run()
} catch {
    fputs("SLM batch failed: \(error.localizedDescription)\n", stderr)
    exit(1)
}

