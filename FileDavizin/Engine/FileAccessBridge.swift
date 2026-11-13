import UIKit

enum FileAccessBridge {
    static func initialize() {
        _ = FDContainerEngineInit()
    }

    static func discoverContainer(bundleID: String) -> String? {
        FDDiscoverContainerPath(bundleID)
    }

    static func grantAccess(path: String) -> Int64 {
        FDGrantAccess(path)
    }

    static func releaseAccess(handle: Int64) {
        FDReleaseAccess(handle)
    }

    static func enumerateInstalledApps(limit: Int = 500) -> [(identifier: String, path: String)] {
        let raw = FDEnumerateApps(UInt(limit))
        return raw.compactMap { dict in
            guard let ident = dict["identifier"] else { return nil }
            let path = dict["path"] ?? ""
            return (identifier: ident, path: path)
        }
    }

    static func discoverAllContainers() -> [AppContainer] {
        let raw = enumerateInstalledApps()
        return raw.map { AppContainer(identifier: $0.identifier, path: $0.path) }
    }

    static func deleteItem(at path: String) -> Bool {
        deleteFile(at: path)
    }

    static func copyItem(from sourcePath: String, to destPath: String) -> Bool {
        copyFile(from: sourcePath, to: destPath)
    }

    static func canWrite(at path: String) -> Bool {
        FDCanWrite(path)
    }

    static func listDirectory(at path: String) -> [FileNode] {
        let fm = FileManager.default
        if let entries = try? fm.contentsOfDirectory(atPath: path) {
            return entries.compactMap { name in
                fileNode(name: name, parentPath: path)
            }.sorted()
        }
        let _ = grantAccess(path: path)
        if let entries = try? fm.contentsOfDirectory(atPath: path) {
            return entries.compactMap { name in
                fileNode(name: name, parentPath: path)
            }.sorted()
        }
        let parent = (path as NSString).deletingLastPathComponent
        if parent.count > 1 {
            let _ = grantAccess(path: parent)
            if let entries = try? fm.contentsOfDirectory(atPath: path) {
                return entries.compactMap { name in
                    fileNode(name: name, parentPath: path)
                }.sorted()
            }
        }
        NSLog("[FD] listDirectory FAILED: %@", path)
        return []
    }

    static func readFile(at path: String) -> Data? {
        if let data = FileManager.default.contents(atPath: path) {
            return data
        }
        let dir = (path as NSString).deletingLastPathComponent
        let _ = grantAccess(path: dir)
        return FileManager.default.contents(atPath: path)
    }

    static func fileSize(at path: String) -> UInt64 {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attrs[.size] as? UInt64 else { return 0 }
        return size
    }

    static func copyFile(from sourcePath: String, to destPath: String) -> Bool {
        do {
            try FileManager.default.copyItem(atPath: sourcePath, toPath: destPath)
            return true
        } catch {
            NSLog("[FD] copyFile error: %@", error.localizedDescription)
            return false
        }
    }

    static func deleteFile(at path: String) -> Bool {
        do {
            try FileManager.default.removeItem(atPath: path)
            return true
        } catch {
            NSLog("[FD] deleteFile error: %@", error.localizedDescription)
            return false
        }
    }

    static func shareFile(at path: String, from viewController: UIViewController) {
        let url = URL(fileURLWithPath: path)
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fd_share", isDirectory: true)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let tempURL = tempDir.appendingPathComponent(url.lastPathComponent)
        try? FileManager.default.removeItem(at: tempURL)

        if FileAccessBridge.copyFile(from: path, to: tempURL.path) {
            let ac = UIActivityViewController(activityItems: [tempURL], applicationActivities: nil)
            if let popover = ac.popoverPresentationController {
                popover.sourceView = viewController.view
                popover.sourceRect = CGRect(x: viewController.view.bounds.midX,
                                            y: viewController.view.bounds.midY,
                                            width: 0, height: 0)
            }
            viewController.present(ac, animated: true)
        }
    }

    private static func fileNode(name: String, parentPath: String) -> FileNode? {
        let fullPath = (parentPath as NSString).appendingPathComponent(name)
        var isDir: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: fullPath, isDirectory: &isDir)
        guard exists else { return nil }

        let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath)
        let size = attrs?[.size] as? UInt64 ?? 0
        let modified = attrs?[.modificationDate] as? Date

        return FileNode(
            name: name,
            path: fullPath,
            isDirectory: isDir.boolValue,
            size: size,
            modifiedDate: modified
        )
    }
}
