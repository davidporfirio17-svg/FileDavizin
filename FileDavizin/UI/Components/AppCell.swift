import UIKit

final class AppCell: UICollectionViewCell {
    static let reuseID = "AppCell"

    private let iconView = UIImageView()
    private let fallbackLabel = UILabel()
    private let bundleLabel = UILabel()
    private let pathLabel = UILabel()
    private let chevron = UIImageView()

    override init(frame: CGRect) {
        super.init(frame: frame)
        setup()
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    private func setup() {
        contentView.backgroundColor = FDTheme.card
        contentView.layer.cornerRadius = FDTheme.controlCornerRadius

        iconView.contentMode = .scaleAspectFit
        iconView.layer.cornerRadius = 10
        iconView.clipsToBounds = true
        iconView.translatesAutoresizingMaskIntoConstraints = false

        fallbackLabel.font = .systemFont(ofSize: 16, weight: .bold)
        fallbackLabel.textAlignment = .center
        fallbackLabel.translatesAutoresizingMaskIntoConstraints = false
        iconView.addSubview(fallbackLabel)

        bundleLabel.font = FDTheme.controlFont()
        bundleLabel.textColor = FDTheme.primaryText
        bundleLabel.lineBreakMode = .byTruncatingMiddle

        pathLabel.font = FDTheme.monoFont(10)
        pathLabel.textColor = FDTheme.tertiaryText
        pathLabel.lineBreakMode = .byTruncatingMiddle

        let textStack = UIStackView(arrangedSubviews: [bundleLabel, pathLabel])
        textStack.axis = .vertical
        textStack.spacing = 3

        chevron.image = UIImage(systemName: "chevron.right")?.withConfiguration(
            UIImage.SymbolConfiguration(pointSize: 12, weight: .semibold))
        chevron.tintColor = FDTheme.tertiaryText
        chevron.setContentHuggingPriority(.required, for: .horizontal)

        let hStack = UIStackView(arrangedSubviews: [iconView, textStack, chevron])
        hStack.axis = .horizontal
        hStack.spacing = 12
        hStack.alignment = .center
        hStack.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(hStack)

        NSLayoutConstraint.activate([
            iconView.widthAnchor.constraint(equalToConstant: 40),
            iconView.heightAnchor.constraint(equalToConstant: 40),
            fallbackLabel.centerXAnchor.constraint(equalTo: iconView.centerXAnchor),
            fallbackLabel.centerYAnchor.constraint(equalTo: iconView.centerYAnchor),
            hStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 14),
            hStack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -14),
            hStack.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            hStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -12)
        ])
    }

    func configure(with container: AppContainer) {
        bundleLabel.text = container.displayName + " — " + container.identifier
        pathLabel.text = container.cachedSize.isEmpty ? container.shortPath : container.cachedSize

        if let icon = container.iconImage {
            iconView.image = icon
            iconView.backgroundColor = .clear
            fallbackLabel.isHidden = true
        } else {
            iconView.image = nil
            fallbackLabel.isHidden = false
            fallbackLabel.text = container.iconLetter
            let hue = CGFloat(abs(container.identifier.hashValue) % 360) / 360.0
            iconView.backgroundColor = UIColor(hue: hue, saturation: 0.55, brightness: 0.30, alpha: 1)
            fallbackLabel.textColor = UIColor(hue: hue, saturation: 0.40, brightness: 0.90, alpha: 1)
        }
    }
}
