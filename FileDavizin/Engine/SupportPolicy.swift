import Foundation
import Darwin
import UIKit

enum FDDeviceInfo {
    static var osVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }

    static var versionTuple: (major: Int, minor: Int, patch: Int) {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return (v.majorVersion, v.minorVersion, v.patchVersion)
    }

    static var machineName: String {
        var s = utsname()
        uname(&s)
        return Mirror(reflecting: s.machine).children.reduce("") { id, e in
            guard let v = e.value as? Int8, v != 0 else { return id }
            return id + String(UnicodeScalar(UInt8(v)))
        }
    }

    static var displayMachineName: String {
        #if targetEnvironment(simulator)
        return ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? machineName
        #else
        return machineName
        #endif
    }

    static var deviceModel: String {
        modelName(for: displayMachineName)
    }

    static func modelName(for hw: String) -> String {
        switch hw {
        case "iPhone12,1": return "iPhone 11"
        case "iPhone12,3": return "iPhone 11 Pro"
        case "iPhone12,5": return "iPhone 11 Pro Max"
        case "iPhone12,8": return "iPhone SE (2nd gen)"
        case "iPhone13,1": return "iPhone 12 mini"
        case "iPhone13,2": return "iPhone 12"
        case "iPhone13,3": return "iPhone 12 Pro"
        case "iPhone13,4": return "iPhone 12 Pro Max"
        case "iPhone14,4": return "iPhone 13 mini"
        case "iPhone14,5": return "iPhone 13"
        case "iPhone14,2": return "iPhone 13 Pro"
        case "iPhone14,3": return "iPhone 13 Pro Max"
        case "iPhone14,6": return "iPhone SE (3rd gen)"
        case "iPhone14,7": return "iPhone 14"
        case "iPhone14,8": return "iPhone 14 Plus"
        case "iPhone15,2": return "iPhone 14 Pro"
        case "iPhone15,3": return "iPhone 14 Pro Max"
        case "iPhone15,4": return "iPhone 15"
        case "iPhone15,5": return "iPhone 15 Plus"
        case "iPhone16,1": return "iPhone 15 Pro"
        case "iPhone16,2": return "iPhone 15 Pro Max"
        case "iPhone17,3": return "iPhone 16"
        case "iPhone17,4": return "iPhone 16 Plus"
        case "iPhone17,1": return "iPhone 16 Pro"
        case "iPhone17,2": return "iPhone 16 Pro Max"
        case "iPhone17,5": return "iPhone 16e"
        case "iPhone18,3": return "iPhone 17"
        case "iPhone18,1": return "iPhone 17 Pro"
        case "iPhone18,2": return "iPhone 17 Pro Max"
        case "iPhone18,4": return "iPhone Air"
        case "iPhone18,5": return "iPhone 17e"
        case "iPhone19,2": return "iPhone 18 Pro"
        case "iPhone19,3", "iPhone19,7": return "iPhone 18 Pro Max"
        case "iPhone19,4": return "iPhone Duo"
        default:
            if hw.hasPrefix("iPad") { return "iPad (\(hw))" }
            return hw
        }
    }

    static var osBuild: String {
        var size = 0
        guard sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 0 else { return "" }
        var buffer = [CChar](repeating: 0, count: size)
        let result = buffer.withUnsafeMutableBufferPointer { pointer in
            sysctlbyname("kern.osversion", pointer.baseAddress, &size, nil, 0)
        }
        guard result == 0 else { return "" }
        return String(cString: buffer)
    }

    static var systemDescription: String {
        let v = versionTuple
        let build = osBuild
        let ver = "\(v.major).\(v.minor).\(v.patch)"
        return build.isEmpty ? "iOS \(ver)" : "iOS \(ver) (\(build))"
    }
}

enum FDSupportPolicy {
    static var currentVersion: OperatingSystemVersion {
        ProcessInfo.processInfo.operatingSystemVersion
    }

    static func isSupported(major: Int, minor: Int, patch: Int) -> Bool {
        major >= 17 && major <= 27
    }

    static var isCurrentSystemSupported: Bool {
        let v = currentVersion
        return isSupported(major: v.majorVersion, minor: v.minorVersion, patch: v.patchVersion)
    }

    static var supportedRangesDescription: String {
        "iOS 17.0–27.x"
    }

    static var statusLabel: String {
        isCurrentSystemSupported ? "Compatible" : "No compatible"
    }

    static func systemSummary() -> String {
        """
        Device: \(FDDeviceInfo.deviceModel)
        iOS: \(FDDeviceInfo.systemDescription)
        Status: \(statusLabel)
        Range: \(supportedRangesDescription)
        """
    }
}
