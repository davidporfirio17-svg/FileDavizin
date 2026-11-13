import Foundation

enum SandboxStatus {
    case idle
    case initializing
    case ready(method: String)
    case failed(String)

    var isReady: Bool {
        if case .ready = self { return true }
        return false
    }

    var displayText: String {
        switch self {
        case .idle: return "Esperando..."
        case .initializing: return "Preparando acceso..."
        case .ready(let method): return "Listo (\(method))"
        case .failed(let msg): return "Error: \(msg)"
        }
    }
}

final class SandboxManager {
    static let shared = SandboxManager()

    private(set) var status: SandboxStatus = .idle
    private let lock = NSLock()

    static let statusDidChange = Notification.Name("FDSandboxStatusDidChange")

    private init() {}

    func prepareAccess() {
        lock.lock()
        guard case .idle = status else { lock.unlock(); return }
        status = .initializing
        lock.unlock()
        postStatus()

        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let result = runEscapeSequence()
            lock.lock()
            status = result
            lock.unlock()
            postStatus()
        }
    }

    private func runEscapeSequence() -> SandboxStatus {
        let ver = FDDeviceInfo.versionTuple
        let requiresPairing = ver.major >= 27

        NSLog("[FD] Escape sequence: iOS %d.%d.%d requiresPairing=%d",
              ver.major, ver.minor, ver.patch, requiresPairing ? 1 : 0)

        // Step 1: Initialize container engine (WQ-SYM on 4 base paths)
        FDContainerEngineInit()

        // Step 2: Check if WQ-SYM alone was enough
        if requiresPairing {
            NSLog("[FD] iOS 27+: per-container grants via worse_query")
            return .ready(method: "WQ-SYM")
        }

        if sandbox_access_is_active() != 0 {
            NSLog("[FD] Sandbox already active after WQ-SYM")
            return .ready(method: "WQ-SYM")
        }

        // Step 3: Check if kernel offsets are supported for kexploit
        let supportsKernel = FDSupportPolicy.isSupported(
            major: ver.major, minor: ver.minor, patch: ver.patch
        )
        guard supportsKernel else {
            NSLog("[FD] No kernel offsets for iOS %d.%d — WQ-SYM only mode", ver.major, ver.minor)
            return .ready(method: "WQ-SYM (parcial)")
        }

        // Step 4: Try kexploit
        NSLog("[FD] WQ-SYM insufficient, running kexploit_opa334...")
        let exploitResult = kexploit_opa334()
        guard exploitResult == 0 else {
            let code = abs(exploitResult)
            let msg = "KXP-\(code)"
            NSLog("[FD] kexploit failed: %@", msg)
            return .ready(method: "WQ-SYM (sin kexploit)")
        }

        // Step 5: Sandbox escape
        NSLog("[FD] kexploit OK, running sandbox_escape...")
        let selfProc = proc_self()
        let escapeResult = sandbox_escape(selfProc)
        let active = sandbox_access_is_active() != 0

        NSLog("[FD] sandbox_escape=%d active=%d", escapeResult, active ? 1 : 0)

        if active {
            let _ = sandbox_set_platform_binary(selfProc)
            return .ready(method: "kexploit + sandbox_escape")
        }

        return .ready(method: "WQ-SYM (escape parcial)")
    }

    private func postStatus() {
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: Self.statusDidChange, object: self.status)
        }
    }
}
