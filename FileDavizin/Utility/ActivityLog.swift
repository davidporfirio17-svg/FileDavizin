import Foundation

final class FDLogStore {
    static let shared = FDLogStore()
    static let didUpdate = Notification.Name("FDLogStoreDidUpdate")

    private let lock = NSLock()
    private var entries: [String] = []
    private let maxEntries = 2000

    private init() {
        redirectStderr()
    }

    var allText: String {
        lock.lock()
        defer { lock.unlock() }
        return entries.joined(separator: "\n")
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }

    func append(_ line: String) {
        lock.lock()
        entries.append(line)
        if entries.count > maxEntries {
            entries.removeFirst(entries.count - maxEntries)
        }
        lock.unlock()
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: Self.didUpdate, object: nil)
        }
    }

    func clear() {
        lock.lock()
        entries.removeAll()
        lock.unlock()
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: Self.didUpdate, object: nil)
        }
    }

    private func redirectStderr() {
        let pipe = Pipe()
        dup2(pipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO)
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let str = String(data: data, encoding: .utf8) else { return }
            let lines = str.components(separatedBy: .newlines).filter { !$0.isEmpty }
            for line in lines {
                self?.append(line)
            }
        }
    }
}

enum FDLog {
    static func info(_ msg: String) {
        let line = "[\(timestamp())] INFO: \(msg)"
        FDLogStore.shared.append(line)
        NSLog("[FileDavizin] INFO: %@", msg)
    }
    static func error(_ msg: String) {
        let line = "[\(timestamp())] ERROR: \(msg)"
        FDLogStore.shared.append(line)
        NSLog("[FileDavizin] ERROR: %@", msg)
    }
    static func success(_ msg: String) {
        let line = "[\(timestamp())] OK: \(msg)"
        FDLogStore.shared.append(line)
        NSLog("[FileDavizin] OK: %@", msg)
    }
    private static func timestamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f.string(from: Date())
    }
}
