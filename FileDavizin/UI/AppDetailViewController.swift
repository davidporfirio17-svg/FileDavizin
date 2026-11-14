import UIKit

final class AppDetailViewController: UITableViewController {
    private var container: AppContainer

    init(container: AppContainer) {
        self.container = container
        super.init(style: .insetGrouped)
        title = container.displayName
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = FDTheme.background
        tableView.backgroundColor = FDTheme.background

        if container.bundlePath == nil {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                let bp = FileAccessBridge.resolveBundlePath(bundleID: self.container.identifier)
                if let bp {
                    DispatchQueue.main.async {
                        self.container.bundlePath = bp
                        self.tableView.reloadData()
                    }
                }
            }
        }

        if container.iconImage == nil {
            DispatchQueue.global(qos: .utility).async { [weak self] in
                guard let self else { return }
                let icon = FileAccessBridge.extractAppIcon(bundleID: self.container.identifier)
                if let icon {
                    DispatchQueue.main.async {
                        self.container.iconImage = icon
                        self.tableView.reloadData()
                    }
                }
            }
        }
    }

    // MARK: - DataSource

    override func numberOfSections(in tableView: UITableView) -> Int { 2 }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        section == 0 ? nil : "Contenedores"
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        if section == 0 { return 1 }
        return container.bundlePath != nil ? 2 : 1
    }

    override func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        indexPath.section == 0 ? 80 : 60
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        if indexPath.section == 0 {
            return makeInfoCell()
        }
        return makeContainerCell(row: indexPath.row)
    }

    private func makeInfoCell() -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = FDTheme.card
        cell.selectionStyle = .none

        let iconSize: CGFloat = 56
        let iconView = UIImageView()
        iconView.contentMode = .scaleAspectFit
        iconView.layer.cornerRadius = 12
        iconView.clipsToBounds = true
        iconView.translatesAutoresizingMaskIntoConstraints = false

        if let icon = container.iconImage {
            iconView.image = icon
        } else {
            iconView.backgroundColor = iconBackgroundColor()
            let lbl = UILabel()
            lbl.text = container.iconLetter
            lbl.font = .systemFont(ofSize: 24, weight: .bold)
            lbl.textColor = iconForegroundColor()
            lbl.textAlignment = .center
            lbl.translatesAutoresizingMaskIntoConstraints = false
            iconView.addSubview(lbl)
            NSLayoutConstraint.activate([
                lbl.centerXAnchor.constraint(equalTo: iconView.centerXAnchor),
                lbl.centerYAnchor.constraint(equalTo: iconView.centerYAnchor),
            ])
        }

        let nameLabel = UILabel()
        nameLabel.text = container.displayName
        nameLabel.font = FDTheme.titleFont(18)
        nameLabel.textColor = FDTheme.primaryText

        let idLabel = UILabel()
        idLabel.text = container.identifier
        idLabel.font = FDTheme.monoFont(11)
        idLabel.textColor = FDTheme.tertiaryText
        idLabel.lineBreakMode = .byTruncatingMiddle

        let textStack = UIStackView(arrangedSubviews: [nameLabel, idLabel])
        textStack.axis = .vertical
        textStack.spacing = 4

        let hStack = UIStackView(arrangedSubviews: [iconView, textStack])
        hStack.axis = .horizontal
        hStack.spacing = 14
        hStack.alignment = .center
        hStack.translatesAutoresizingMaskIntoConstraints = false
        cell.contentView.addSubview(hStack)

        NSLayoutConstraint.activate([
            iconView.widthAnchor.constraint(equalToConstant: iconSize),
            iconView.heightAnchor.constraint(equalToConstant: iconSize),
            hStack.leadingAnchor.constraint(equalTo: cell.contentView.leadingAnchor, constant: 16),
            hStack.trailingAnchor.constraint(equalTo: cell.contentView.trailingAnchor, constant: -16),
            hStack.topAnchor.constraint(equalTo: cell.contentView.topAnchor, constant: 12),
            hStack.bottomAnchor.constraint(equalTo: cell.contentView.bottomAnchor, constant: -12),
        ])

        return cell
    }

    private func makeContainerCell(row: Int) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = FDTheme.card
        cell.accessoryType = .disclosureIndicator
        cell.textLabel?.textColor = FDTheme.primaryText
        cell.textLabel?.font = FDTheme.controlFont()
        cell.detailTextLabel?.textColor = FDTheme.tertiaryText
        cell.detailTextLabel?.font = FDTheme.monoFont(10)
        cell.detailTextLabel?.lineBreakMode = .byTruncatingMiddle

        if row == 0 {
            cell.textLabel?.text = "Datos de la app"
            cell.detailTextLabel?.text = container.shortPath
            cell.imageView?.image = UIImage(systemName: "folder.fill")
            cell.imageView?.tintColor = FDTheme.accent
        } else {
            cell.textLabel?.text = "Paquete de la app (.app)"
            let bp = container.bundlePath ?? ""
            let comps = (bp as NSString).pathComponents
            cell.detailTextLabel?.text = comps.count > 3
                ? ".../" + comps.suffix(2).joined(separator: "/") : bp
            cell.imageView?.image = UIImage(systemName: "shippingbox.fill")
            cell.imageView?.tintColor = FDTheme.warm
        }

        return cell
    }

    // MARK: - Delegate

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard indexPath.section == 1 else { return }

        if indexPath.row == 0 {
            let browser = FileBrowserViewController(
                path: container.path, title: container.displayName)
            navigationController?.pushViewController(browser, animated: true)
        } else if let bp = container.bundlePath {
            let browser = FileBrowserViewController(
                path: bp, title: "Bundle — \(container.displayName)")
            navigationController?.pushViewController(browser, animated: true)
        }
    }

    // MARK: - Helpers

    private func iconBackgroundColor() -> UIColor {
        let hue = CGFloat(abs(container.identifier.hashValue) % 360) / 360.0
        return UIColor(hue: hue, saturation: 0.55, brightness: 0.30, alpha: 1)
    }

    private func iconForegroundColor() -> UIColor {
        let hue = CGFloat(abs(container.identifier.hashValue) % 360) / 360.0
        return UIColor(hue: hue, saturation: 0.40, brightness: 0.90, alpha: 1)
    }
}
