import UIKit

final class FileCell: UITableViewCell {
    static let reuseID = "FileCell"

    private let iconView = UIImageView()
    private let nameLabel = UILabel()
    private let detailLabel = UILabel()
    private let dateLabel = UILabel()

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setup()
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    private func setup() {
        backgroundColor = .clear
        selectionStyle = .none

        iconView.contentMode = .scaleAspectFit
        iconView.tintColor = FDTheme.accent
        iconView.translatesAutoresizingMaskIntoConstraints = false
        iconView.setContentHuggingPriority(.required, for: .horizontal)

        nameLabel.font = FDTheme.bodyFont()
        nameLabel.textColor = FDTheme.primaryText
        nameLabel.lineBreakMode = .byTruncatingMiddle

        detailLabel.font = FDTheme.captionFont()
        detailLabel.textColor = FDTheme.tertiaryText

        dateLabel.font = FDTheme.captionFont()
        dateLabel.textColor = FDTheme.tertiaryText
        dateLabel.textAlignment = .right
        dateLabel.setContentHuggingPriority(.required, for: .horizontal)
        dateLabel.setContentCompressionResistancePriority(.required, for: .horizontal)

        let textStack = UIStackView(arrangedSubviews: [nameLabel, detailLabel])
        textStack.axis = .vertical
        textStack.spacing = 2

        let mainStack = UIStackView(arrangedSubviews: [iconView, textStack, dateLabel])
        mainStack.axis = .horizontal
        mainStack.spacing = 12
        mainStack.alignment = .center
        mainStack.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(mainStack)

        NSLayoutConstraint.activate([
            iconView.widthAnchor.constraint(equalToConstant: 24),
            mainStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            mainStack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            mainStack.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 8),
            mainStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -8)
        ])
    }

    func configure(with node: FileNode) {
        let iconName = node.isSymlink ? "arrow.triangle.turn.up.right.diamond" : node.iconName
        iconView.image = UIImage(systemName: iconName)
        iconView.tintColor = node.isDirectory ? FDTheme.warm : FDTheme.accent
        if node.isHidden {
            nameLabel.textColor = FDTheme.tertiaryText
            iconView.alpha = 0.5
        } else {
            nameLabel.textColor = FDTheme.primaryText
            iconView.alpha = 1.0
        }
        nameLabel.text = node.name
        var detail = node.isDirectory ? "Carpeta" : node.displaySize
        if let perms = node.permissions, perms != "?" {
            detail += "  \(perms)"
        }
        if node.isSymlink { detail += "  (symlink)" }
        detailLabel.text = detail
        dateLabel.text = node.displayDate
        accessoryType = node.isDirectory ? .disclosureIndicator : .none
    }
}
