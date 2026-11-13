import UIKit

final class AppCell: UICollectionViewCell {
    static let reuseID = "AppCell"

    private let iconCircle = UIView()
    private let iconLabel = UILabel()
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

        iconCircle.layer.cornerRadius = 20
        iconCircle.translatesAutoresizingMaskIntoConstraints = false

        iconLabel.font = .systemFont(ofSize: 16, weight: .bold)
        iconLabel.textAlignment = .center
        iconLabel.translatesAutoresizingMaskIntoConstraints = false
        iconCircle.addSubview(iconLabel)

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

        let hStack = UIStackView(arrangedSubviews: [iconCircle, textStack, chevron])
        hStack.axis = .horizontal
        hStack.spacing = 12
        hStack.alignment = .center
        hStack.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(hStack)

        NSLayoutConstraint.activate([
            iconCircle.widthAnchor.constraint(equalToConstant: 40),
            iconCircle.heightAnchor.constraint(equalToConstant: 40),
            iconLabel.centerXAnchor.constraint(equalTo: iconCircle.centerXAnchor),
            iconLabel.centerYAnchor.constraint(equalTo: iconCircle.centerYAnchor),
            hStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 14),
            hStack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -14),
            hStack.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            hStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -12)
        ])
    }

    func configure(with container: AppContainer) {
        bundleLabel.text = container.identifier
        pathLabel.text = container.path
        iconLabel.text = container.iconLetter

        let hue = CGFloat(abs(container.identifier.hashValue) % 360) / 360.0
        let bg = UIColor(hue: hue, saturation: 0.55, brightness: 0.30, alpha: 1)
        let fg = UIColor(hue: hue, saturation: 0.40, brightness: 0.90, alpha: 1)
        iconCircle.backgroundColor = bg
        iconLabel.textColor = fg
    }
}
