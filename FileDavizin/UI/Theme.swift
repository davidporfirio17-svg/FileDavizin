import UIKit

enum FDTheme {
    private static func adaptive(dark: UIColor, light: UIColor) -> UIColor {
        UIColor { $0.userInterfaceStyle == .light ? light : dark }
    }

    static var background: UIColor {
        adaptive(
            dark: UIColor(red: 0.020, green: 0.028, blue: 0.050, alpha: 1),
            light: UIColor(red: 0.950, green: 0.955, blue: 0.968, alpha: 1))
    }
    static var backgroundRaise: UIColor {
        adaptive(
            dark: UIColor(red: 0.050, green: 0.062, blue: 0.090, alpha: 1),
            light: .white)
    }
    static var card: UIColor { backgroundRaise }
    static var hairline: UIColor {
        adaptive(
            dark: UIColor.white.withAlphaComponent(0.09),
            light: UIColor.black.withAlphaComponent(0.10))
    }
    static var hairlineStrong: UIColor {
        adaptive(
            dark: UIColor.white.withAlphaComponent(0.16),
            light: UIColor.black.withAlphaComponent(0.18))
    }

    static var primaryText: UIColor {
        adaptive(
            dark: UIColor(red: 0.950, green: 0.962, blue: 0.980, alpha: 1),
            light: UIColor(red: 0.08, green: 0.10, blue: 0.14, alpha: 1))
    }
    static var secondaryText: UIColor {
        adaptive(
            dark: UIColor(red: 0.78, green: 0.82, blue: 0.88, alpha: 0.72),
            light: UIColor(red: 0.24, green: 0.27, blue: 0.34, alpha: 0.78))
    }
    static var tertiaryText: UIColor {
        adaptive(
            dark: UIColor(red: 0.68, green: 0.74, blue: 0.82, alpha: 0.42),
            light: UIColor(red: 0.32, green: 0.36, blue: 0.44, alpha: 0.55))
    }

    static var accent: UIColor {
        adaptive(
            dark: UIColor(red: 0.20, green: 0.78, blue: 0.72, alpha: 1),
            light: UIColor(red: 0.00, green: 0.44, blue: 0.38, alpha: 1))
    }
    static var accentDim: UIColor { accent.withAlphaComponent(0.18) }
    static var success: UIColor {
        adaptive(
            dark: UIColor(red: 0.42, green: 0.82, blue: 0.69, alpha: 1),
            light: UIColor(red: 0.08, green: 0.39, blue: 0.25, alpha: 1))
    }
    static var failure: UIColor {
        adaptive(
            dark: UIColor(red: 0.98, green: 0.36, blue: 0.40, alpha: 1),
            light: UIColor(red: 0.68, green: 0.13, blue: 0.20, alpha: 1))
    }
    static var warm: UIColor {
        adaptive(
            dark: UIColor(red: 1.00, green: 0.68, blue: 0.26, alpha: 1),
            light: UIColor(red: 0.54, green: 0.29, blue: 0.04, alpha: 1))
    }

    static let cardCornerRadius: CGFloat = 18
    static let controlCornerRadius: CGFloat = 12
    static let standardSpacing: CGFloat = 16
    static let cardPadding: CGFloat = 20
    static let controlHeight: CGFloat = 50

    static func titleFont(_ size: CGFloat = 24) -> UIFont {
        .systemFont(ofSize: size, weight: .bold)
    }
    static func bodyFont() -> UIFont {
        .systemFont(ofSize: 14, weight: .regular)
    }
    static func captionFont() -> UIFont {
        .systemFont(ofSize: 10, weight: .semibold)
    }
    static func controlFont() -> UIFont {
        .systemFont(ofSize: 14, weight: .semibold)
    }
    static func monoFont(_ size: CGFloat = 12) -> UIFont {
        .monospacedSystemFont(ofSize: size, weight: .medium)
    }
}

extension UIView {
    func fdPinEdges(to other: UIView, insets: UIEdgeInsets = .zero) {
        translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            leadingAnchor.constraint(equalTo: other.leadingAnchor, constant: insets.left),
            trailingAnchor.constraint(equalTo: other.trailingAnchor, constant: -insets.right),
            topAnchor.constraint(equalTo: other.topAnchor, constant: insets.top),
            bottomAnchor.constraint(equalTo: other.bottomAnchor, constant: -insets.bottom)
        ])
    }
}
