/*
 *  (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

import Foundation
import ArgumentParser
import SQLite

enum ProvenanceError: Error {
    case notRunningAsRoot
    case databaseError(Error)
    case extendedAttributeError(POSIXError)
    case invalidData
}

struct ProvenanceTracking: Codable {
    let pk: Int64
    let url: String
    let bundleId: String?
    let cdhash: String?
    let teamIdentifier: String?
    let signingIdentifier: String?
    let flags: Int64?
    let timestamp: Int64
    let linkPk: Int64?
}

struct ProvenanceResult: Codable {
    let filePath: String
    let creator: String
    let pk: String
    let timestamp: Int64?
    let bundleId: String?
    let teamIdentifier: String?
    let signingIdentifier: String?
}

final class ProvenanceScanner {
    private let provenanceEntries: [Int64: ProvenanceTracking]
    private let outputFormat: OutputFormat
    
    enum OutputFormat {
        case text
        case json
    }
    
    init(provenanceEntries: [Int64: ProvenanceTracking], outputFormat: OutputFormat) {
        self.provenanceEntries = provenanceEntries
        self.outputFormat = outputFormat
    }
    
    private func log(_ message: String) {
        if case .text = outputFormat {
            print(message)
        }
    }
    
    func scanFile(at url: URL) throws {
        let pk = try extractPk(from: url)
        let entry = provenanceEntries[pk]
        
        switch outputFormat {
        case .text:
            print("\(url.absoluteString) was created/modified by \(entry?.url ?? "N/A")")
        case .json:
            let result = ProvenanceResult(
                filePath: url.absoluteString,
                creator: entry?.url ?? "N/A",
                pk: String(format: "0x%016llx", pk),
                timestamp: entry?.timestamp,
                bundleId: entry?.bundleId,
                teamIdentifier: entry?.teamIdentifier,
                signingIdentifier: entry?.signingIdentifier
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let jsonData = try encoder.encode(result)
            if let jsonString = String(data: jsonData, encoding: .utf8) {
                print(jsonString)
            }
        }
    }
    
    func scanDirectoryRecursively(at url: URL) {
        guard let enumerator = FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil, options: []) else {
            log("Failed to create directory enumerator for \(url)")
            return
        }
        
        var results: [ProvenanceResult] = []
        
        for case let fileURL as URL in enumerator {
            do {
                let pk = try extractPk(from: fileURL)
                let entry = provenanceEntries[pk]
                
                switch outputFormat {
                case .text:
                    print("\(fileURL.absoluteString) was created/modified by \(entry?.url ?? "N/A")")
                case .json:
                    let result = ProvenanceResult(
                        filePath: fileURL.absoluteString,
                        creator: entry?.url ?? "N/A",
                        pk: String(format: "0x%016llx", pk),
                        timestamp: entry?.timestamp,
                        bundleId: entry?.bundleId,
                        teamIdentifier: entry?.teamIdentifier,
                        signingIdentifier: entry?.signingIdentifier
                    )
                    results.append(result)
                }
            } catch POSIXError.ENOATTR {
                continue
            } catch {
                log("Error scanning \(fileURL): \(error)")
            }
        }
        
        if case .json = outputFormat {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            if let jsonData = try? encoder.encode(results),
               let jsonString = String(data: jsonData, encoding: .utf8) {
                print(jsonString)
            }
        }
    }
    
    private func extractPk(from url: URL) throws -> Int64 {
        let data = try getExtendedAttributes(url: url, name: "com.apple.provenance")
        guard data.count >= 11 else { throw ProvenanceError.invalidData }
        
        let pkData = Data(data[3..<11])
        return pkData.withUnsafeBytes { $0.load(as: Int64.self) }
    }
}

final class ProvenanceDatabase {
    static func load() throws -> [Int64: ProvenanceTracking] {
        var provenanceEntries: [Int64: ProvenanceTracking] = [:]
        
        let db = try Connection("/private/var/db/SystemPolicyConfiguration/ExecPolicy")
        let provenanceTracking = Table("provenance_tracking")
        
        let pk = Expression<Int64>("pk")
        let url = Expression<String>("url")
        let bundleId = Expression<String?>("bundle_id")
        let cdhash = Expression<String?>("cdhash")
        let teamIdentifier = Expression<String?>("team_identifier")
        let signingIdentifier = Expression<String?>("signing_identifier")
        let flags = Expression<Int64?>("flags")
        let timestamp = Expression<Int64>("timestamp")
        let linkPk = Expression<Int64?>("link_pk")
        
        for entry in try db.prepare(provenanceTracking) {
            let tracking = ProvenanceTracking(
                pk: entry[pk],
                url: entry[url],
                bundleId: entry[bundleId],
                cdhash: entry[cdhash],
                teamIdentifier: entry[teamIdentifier],
                signingIdentifier: entry[signingIdentifier],
                flags: entry[flags],
                timestamp: entry[timestamp],
                linkPk: entry[linkPk]
            )
            provenanceEntries[entry[pk]] = tracking
        }
        
        return provenanceEntries
    }
}

func getExtendedAttributes(url: URL, name: String) throws -> Data {
    try url.withUnsafeFileSystemRepresentation { fileSystemPath -> Data in
        let length = getxattr(fileSystemPath, name, nil, 0, 0, 0)
        guard length >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }
        
        var data = Data(count: length)
        let result = data.withUnsafeMutableBytes { [count = data.count] in
            getxattr(fileSystemPath, name, $0.baseAddress, count, 0, 0)
        }
        guard result >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno)!) }
        return data
    }
}

@main
struct ShowProvenanceInfo: ParsableCommand {
    @Argument(help: "Path to the file to show provenance information")
    var path: String
    
    @Flag(name: .short, help: "Output in JSON format")
    var jsonOutput = false
    
    mutating func run() throws {
        guard getuid() == 0 else {
            throw ProvenanceError.notRunningAsRoot
        }
        
        let outputFormat: ProvenanceScanner.OutputFormat = jsonOutput ? .json : .text
        let scanner = ProvenanceScanner(provenanceEntries: try ProvenanceDatabase.load(), outputFormat: outputFormat)
        
        if case .text = outputFormat {
            print("Loading /private/var/db/SystemPolicyConfiguration/ExecPolicy")
        }
        
        let url = URL(fileURLWithPath: path)
        if url.hasDirectoryPath {
            if case .text = outputFormat {
                print("Scanning directory")
            }
            scanner.scanDirectoryRecursively(at: url)
        } else {
            if case .text = outputFormat {
                print("Scanning file")
            }
            try scanner.scanFile(at: url)
        }
    }
}