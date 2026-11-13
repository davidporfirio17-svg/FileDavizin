import Foundation

struct AppContainer: Hashable {
    let identifier: String
    let path: String

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

    var containerSize: String {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return "N/A" }
        guard let contents = try? fm.contentsOfDirectory(atPath: path) else { return "N/A" }
        return "\(contents.count) items"
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
