import Foundation

struct AppContainer: Hashable {
    let identifier: String
    let path: String
    var cachedSize: String = ""

    var displayName: String {
        let parts = identifier.split(separator: ".")
        if let last = parts.last, last.count > 1 {
            return String(last).capitalized
        }
        return identifier
    }

    var shortIdentifier: String {
        let parts = identifier.split(separator: ".")
        if parts.count > 2 {
            return parts.suffix(2).joined(separator: ".")
        }
        return identifier
    }

    var iconLetter: String {
        String(displayName.prefix(1)).uppercased()
    }

    var shortPath: String {
        let comps = (path as NSString).pathComponents
        if comps.count > 3 {
            return ".../" + comps.suffix(2).joined(separator: "/")
        }
        return path
    }

    mutating func computeSize() {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { cachedSize = "N/A"; return }
        if let contents = try? fm.contentsOfDirectory(atPath: path) {
            cachedSize = "\(contents.count) items"
            return
        }
        let _ = FDGrantAccess(path)
        if let contents = try? fm.contentsOfDirectory(atPath: path) {
            cachedSize = "\(contents.count) items"
        } else {
            cachedSize = "---"
        }
    }

    var metadataIdentifier: String? {
        let plist = (path as NSString).appendingPathComponent(
            ".com.apple.mobile_container_manager.metadata.plist")
        guard let dict = NSDictionary(contentsOfFile: plist) else { return nil }
        return dict["MCMMetadataIdentifier"] as? String
    }

    func hash(into hasher: inout Hasher) { hasher.combine(identifier) }
    static func == (lhs: AppContainer, rhs: AppContainer) -> Bool {
        lhs.identifier == rhs.identifier
    }
}
