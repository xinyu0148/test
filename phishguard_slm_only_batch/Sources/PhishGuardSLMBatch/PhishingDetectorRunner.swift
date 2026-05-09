import CoreML
import Foundation

final class WordPieceTokenizer {
    private var vocab: [String: Int] = [:]
    private let unkId: Int
    private let clsId: Int
    private let sepId: Int
    private let padId: Int
    let maxLen: Int

    init(jsonURL: URL, maxLen: Int) throws {
        self.maxLen = maxLen

        let data = try Data(contentsOf: jsonURL)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let model = json["model"] as? [String: Any],
              let vocab = model["vocab"] as? [String: Int] else {
            throw LocalAnalysisError.invalidTokenizer
        }

        self.vocab = vocab
        self.unkId = vocab["[UNK]"] ?? 100
        self.clsId = vocab["[CLS]"] ?? 101
        self.sepId = vocab["[SEP]"] ?? 102
        self.padId = vocab["[PAD]"] ?? 0
    }

    func encode(_ text: String) -> (inputIds: [Int32], attentionMask: [Int32]) {
        let cleaned = text.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        let words = splitOnPunctuation(cleaned)

        var ids: [Int] = [clsId]

        for word in words {
            let subIds = wordpiece(word)
            if ids.count + subIds.count >= maxLen - 1 {
                let space = maxLen - 1 - ids.count
                if space > 0 {
                    ids.append(contentsOf: subIds.prefix(space))
                }
                break
            }
            ids.append(contentsOf: subIds)
        }
        ids.append(sepId)

        let realLen = ids.count
        let pad = maxLen - realLen

        var inputIds = ids.map { Int32($0) }
        var mask = [Int32](repeating: 1, count: realLen)

        if pad > 0 {
            inputIds += [Int32](repeating: Int32(padId), count: pad)
            mask += [Int32](repeating: 0, count: pad)
        }

        return (inputIds, mask)
    }

    private func splitOnPunctuation(_ text: String) -> [String] {
        var tokens: [String] = []
        var current = ""

        for character in text {
            if character.isWhitespace {
                if !current.isEmpty {
                    tokens.append(current)
                    current = ""
                }
            } else if isPunctuation(character) {
                if !current.isEmpty {
                    tokens.append(current)
                    current = ""
                }
                tokens.append(String(character))
            } else {
                current.append(character)
            }
        }

        if !current.isEmpty {
            tokens.append(current)
        }
        return tokens
    }

    private func wordpiece(_ token: String) -> [Int] {
        if token.count > 200 {
            return [unkId]
        }

        var ids: [Int] = []
        var start = token.startIndex

        while start < token.endIndex {
            var end = token.endIndex
            var found = false

            while start < end {
                let subtoken = start == token.startIndex
                    ? String(token[start..<end])
                    : "##" + String(token[start..<end])

                if let id = vocab[subtoken] {
                    ids.append(id)
                    start = end
                    found = true
                    break
                }

                end = token.index(before: end)
            }

            if !found {
                ids.append(unkId)
                start = token.index(after: start)
            }
        }

        return ids
    }

    private func isPunctuation(_ character: Character) -> Bool {
        guard let scalar = character.unicodeScalars.first else {
            return false
        }

        let value = scalar.value
        return (value >= 33 && value <= 47)
            || (value >= 58 && value <= 64)
            || (value >= 91 && value <= 96)
            || (value >= 123 && value <= 126)
            || CharacterSet.punctuationCharacters.contains(scalar)
    }
}

final class PhishingDetectorRunner {
    private let model: MLModel
    private let tokenizer: WordPieceTokenizer
    private let maxLen = 256
    private let labels = ["legitimate_email", "phishing_url", "legitimate_url", "phishing_url_alt"]

    init(modelURL: URL, tokenizerURL: URL) throws {
        let config = MLModelConfiguration()
        config.computeUnits = .all
        let loadableModelURL = try Self.loadableModelURL(from: modelURL)
        print("[PhishingDetector] loading model from: \(loadableModelURL.lastPathComponent)")
        self.model = try MLModel(contentsOf: loadableModelURL, configuration: config)
        self.tokenizer = try WordPieceTokenizer(jsonURL: tokenizerURL, maxLen: maxLen)
        print("[PhishingDetector] tokenizer loaded successfully from: \(tokenizerURL.lastPathComponent)")
    }

    convenience init(bundle: Bundle = .main) throws {
        let compiledModelURL = bundle.url(forResource: "PhishingDetector", withExtension: "mlmodelc")
        let packageModelURL = bundle.url(forResource: "PhishingDetector", withExtension: "mlpackage")
        let tokenizerURL = bundle.url(forResource: "tokenizer", withExtension: "json")

        print("[PhishingDetector] model(.mlmodelc) found: \(compiledModelURL != nil)")
        print("[PhishingDetector] model(.mlpackage) found: \(packageModelURL != nil)")
        print("[PhishingDetector] tokenizer found: \(tokenizerURL != nil)")

        guard let modelURL = compiledModelURL ?? packageModelURL else {
            throw LocalAnalysisError.missingResource("PhishingDetector model")
        }

        guard let tokenizerURL else {
            throw LocalAnalysisError.missingResource("tokenizer.json")
        }

        try self.init(modelURL: modelURL, tokenizerURL: tokenizerURL)
    }

    func detect(_ text: String) throws -> OnDevicePhishingResult {
        let encoded = tokenizer.encode(text)
        
        
        print("[SLM INPUT]", text)
        print("[INPUT IDS FIRST 40]", Array(encoded.inputIds.prefix(40)))
        print("[MASK FIRST 40]", Array(encoded.attentionMask.prefix(40)))
        print("[UNK COUNT]", encoded.inputIds.filter { $0 == 100 }.count)
        
        
        
        let idsArray = try MLMultiArray(shape: [1, NSNumber(value: maxLen)], dataType: .int32)
        let maskArray = try MLMultiArray(shape: [1, NSNumber(value: maxLen)], dataType: .int32)

        for index in 0..<maxLen {
            idsArray[index] = NSNumber(value: encoded.inputIds[index])
            maskArray[index] = NSNumber(value: encoded.attentionMask[index])
        }

        let input = try MLDictionaryFeatureProvider(dictionary: [
            "input_ids": MLFeatureValue(multiArray: idsArray),
            "attention_mask": MLFeatureValue(multiArray: maskArray),
        ])
        let output = try model.prediction(from: input)

        guard let probabilitiesArray = output.featureValue(for: "probabilities")?.multiArrayValue else {
            throw LocalAnalysisError.invalidModelOutput
        }

        let probabilities = (0..<labels.count).map { Double(truncating: probabilitiesArray[$0]) }
        var allProbabilities: [String: Double] = [:]
        for (index, label) in labels.enumerated() {
            allProbabilities[label] = probabilities[index]
        }

        let maxIndex = probabilities.enumerated().max(by: { $0.element < $1.element })?.offset ?? 0
        let phishingRisk = probabilities[1] + probabilities[3]
        let probabilitySummary = labels.enumerated().map { index, label in
            "\(label)=\(String(format: "%.4f", probabilities[index]))"
        }.joined(separator: ", ")
        print("[PhishingDetector] inference success: \(probabilitySummary)")

        return OnDevicePhishingResult(
            prediction: labels[maxIndex],
            confidence: probabilities[maxIndex],
            isPhishing: phishingRisk > 0.5,
            phishingRisk: phishingRisk,
            allProbabilities: allProbabilities
        )
    }

    func debugEncode(_ text: String) -> (inputIds: [Int32], attentionMask: [Int32]) {
        tokenizer.encode(text)
    }

    private static func loadableModelURL(from modelURL: URL) throws -> URL {
        guard modelURL.pathExtension == "mlpackage" else {
            return modelURL
        }

        let compiledURL = try MLModel.compileModel(at: modelURL)
        print("[PhishingDetector] compiled mlpackage to: \(compiledURL.lastPathComponent)")
        return compiledURL
    }
}
