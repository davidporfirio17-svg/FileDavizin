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

    var iconLetter: String {
        String(displayName.prefix(1)).uppercased()
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
