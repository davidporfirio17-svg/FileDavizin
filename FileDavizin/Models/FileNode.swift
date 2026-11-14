import Foundation

struct FileNode: Comparable {
    let name: String
    let path: String
    let isDirectory: Bool
    let size: UInt64
    let modifiedDate: Date?
    let isHidden: Bool
    let isSymlink: Bool
    let permissions: String?

    init(name: String, path: String, isDirectory: Bool, size: UInt64, modifiedDate: Date?,
         isHidden: Bool = false, isSymlink: Bool = false, permissions: String? = nil) {
        self.name = name
        self.path = path
        self.isDirectory = isDirectory
        self.size = size
        self.modifiedDate = modifiedDate
        self.isHidden = isHidden
        self.isSymlink = isSymlink
        self.permissions = permissions
    }

    static func < (lhs: FileNode, rhs: FileNode) -> Bool {
        if lhs.isDirectory != rhs.isDirectory { return lhs.isDirectory }
        return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
    }

    var displaySize: String {
        if isDirectory { return "" }
        switch size {
        case 0..<1024:
            return "\(size) B"
        case 1024..<1_048_576:
            return String(format: "%.1f KB", Double(size) / 1024)
        case 1_048_576..<1_073_741_824:
            return String(format: "%.1f MB", Double(size) / 1_048_576)
        default:
            return String(format: "%.2f GB", Double(size) / 1_073_741_824)
        }
    }

    var fileExtension: String {
        (name as NSString).pathExtension.lowercased()
    }

    var iconName: String {
        if isDirectory { return "folder.fill" }
        switch fileExtension {
        case "png", "jpg", "jpeg", "gif", "heic", "webp", "bmp", "tiff":
            return "photo"
        case "mp4", "mov", "m4v", "avi":
            return "film"
        case "mp3", "m4a", "wav", "aac", "flac":
            return "music.note"
        case "pdf":
            return "doc.richtext"
        case "plist", "xml":
            return "list.bullet.rectangle"
        case "json":
            return "curlybraces"
        case "swift", "m", "h", "c", "cpp", "js", "ts", "py", "rb":
            return "chevron.left.forwardslash.chevron.right"
        case "txt", "md", "log", "csv":
            return "doc.text"
        case "zip", "tar", "gz", "rar", "7z":
            return "doc.zipper"
        case "db", "sqlite", "realm":
            return "cylinder"
        case "ipa", "app":
            return "app"
        default:
            return "doc"
        }
    }

    var displayDate: String? {
        guard let date = modifiedDate else { return nil }
        let formatter = DateFormatter()
        formatter.doesRelativeDateFormatting = true
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}
