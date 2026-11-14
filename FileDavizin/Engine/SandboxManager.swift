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

    private(set) var hasFullEscape = false

    private func runEscapeSequence() -> SandboxStatus {
        let ver = FDDeviceInfo.versionTuple

        NSLog("[FD] Escape sequence: iOS %d.%d.%d",
              ver.major, ver.minor, ver.patch)

        // Step 1: Initialize container engine (WQ-SYM + WQ-PD + MCM-C7 + BQ)
        let accessible = FDContainerEngineInit()
        let active = sandbox_access_is_active()

        NSLog("[FD] Engine init result: accessible=%d sandbox_active=%d",
              accessible, active)

        // Step 2: Always try kexploit for full jailbreak-like access
        let supportsKernel = FDSupportPolicy.isSupported(
            major: ver.major, minor: ver.minor, patch: ver.patch
        )

        if supportsKernel {
            NSLog("[FD] Kernel offsets available, running kexploit_opa334...")
            let exploitResult = kexploit_opa334()

            if exploitResult == 0 {
                NSLog("[FD] kexploit OK, running sandbox_escape...")
                let selfProc = proc_self()

                let escapeResult = sandbox_escape(selfProc)
                NSLog("[FD] sandbox_escape result: %d", escapeResult)

                let _ = sandbox_set_platform_binary(selfProc)
                NSLog("[FD] sandbox_set_platform_binary done")

                let rootResult = sandbox_elevate_to_root(selfProc)
                NSLog("[FD] sandbox_elevate_to_root result: %d", rootResult)

                let activeAfterEscape = sandbox_access_is_active() != 0
                NSLog("[FD] sandbox_active after full escape: %d", activeAfterEscape ? 1 : 0)

                if activeAfterEscape {
                    hasFullEscape = true
                    return .ready(method: "kexploit + root")
                }

                if escapeResult == 0 || rootResult == 0 {
                    hasFullEscape = true
                    return .ready(method: "kexploit (parcial)")
                }
            } else {
                NSLog("[FD] kexploit failed: KXP-%d", abs(exploitResult))
            }
        } else {
            NSLog("[FD] No kernel offsets for iOS %d.%d", ver.major, ver.minor)
        }

        // Step 3: Fallback to WQ-SYM access
        if active != 0 {
            return .ready(method: "WQ-SYM")
        }
        if accessible > 0 {
            return .ready(method: "WQ-SYM (parcial \(accessible))")
        }
        return .ready(method: "WQ (sin verificar)")
    }

    private func postStatus() {
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: Self.statusDidChange, object: self.status)
        }
    }
}
