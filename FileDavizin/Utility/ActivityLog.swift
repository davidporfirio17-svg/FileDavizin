import Foundation

enum FDLog {
    static func info(_ msg: String) {
        NSLog("[FileDavizin] INFO: %@", msg)
    }

    static func error(_ msg: String) {
        NSLog("[FileDavizin] ERROR: %@", msg)
    }

    static func success(_ msg: String) {
        NSLog("[FileDavizin] OK: %@", msg)
    }
}
