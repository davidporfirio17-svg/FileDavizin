import UIKit

final class SystemBrowserViewController: UITableViewController {
    private struct PathEntry {
        let path: String
        let label: String
        let accessible: Bool
        let entryCount: Int
    }

    private struct Section {
        let title: String
        let icon: String
        var entries: [PathEntry]
    }

    private var sections: [Section] = []
    private let spinner = UIActivityIndicatorView(style: .medium)

    init() {
        super.init(style: .insetGrouped)
        title = "Sistema"
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = FDTheme.background
        tableView.backgroundColor = FDTheme.background

        spinner.color = FDTheme.accent
        spinner.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(spinner)
        NSLayoutConstraint.activate([
            spinner.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            spinner.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])

        navigationItem.rightBarButtonItems = [
            UIBarButtonItem(image: UIImage(systemName: "arrow.clockwise"),
                            style: .plain, target: self, action: #selector(refresh)),
            UIBarButtonItem(image: UIImage(systemName: "magnifyingglass"),
                            style: .plain, target: self, action: #selector(goToPath)),
        ]

        spinner.startAnimating()
        loadPaths()
    }

    @objc private func refresh() {
        spinner.startAnimating()
        sections.removeAll()
        tableView.reloadData()
        loadPaths()
    }

    @objc private func goToPath() {
        let alert = UIAlertController(title: "Ir a ruta", message: "Escribe cualquier ruta del filesystem", preferredStyle: .alert)
        alert.addTextField { $0.placeholder = "/private/var/mobile/Library"; $0.autocorrectionType = .no; $0.autocapitalizationType = .none }
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        alert.addAction(UIAlertAction(title: "Ir", style: .default) { [weak self] _ in
            guard let self, let path = alert.textFields?.first?.text, !path.isEmpty else { return }
            let browser = FileBrowserViewController(path: path, title: (path as NSString).lastPathComponent)
            self.navigationController?.pushViewController(browser, animated: true)
        })
        present(alert, animated: true)
    }

    private func loadPaths() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let raw = FDProbeAccessiblePaths() as? [[String: Any]] ?? []

            var categoryMap: [String: (title: String, icon: String, entries: [PathEntry])] = [:]
            let categoryOrder = ["raiz", "sistema", "binarios", "usuario", "media", "contenedores", "var"]
            let categoryTitles: [String: (String, String)] = [
                "raiz":         ("Raiz del Sistema", "externaldrive.fill"),
                "sistema":      ("Sistema", "gearshape.2.fill"),
                "binarios":     ("Binarios y Librerias", "terminal.fill"),
                "usuario":      ("Usuario Mobile", "person.fill"),
                "media":        ("Media", "photo.on.rectangle.angled"),
                "contenedores": ("Contenedores", "shippingbox.fill"),
                "var":          ("Variable del Sistema", "server.rack"),
            ]

            for dict in raw {
                guard let path = dict["path"] as? String,
                      let label = dict["label"] as? String else { continue }
                let accessible = (dict["accessible"] as? Bool) ?? false
                let count = (dict["entryCount"] as? Int) ?? 0
                let cat = (dict["category"] as? String) ?? "var"

                let entry = PathEntry(path: path, label: label, accessible: accessible, entryCount: count)
                if categoryMap[cat] == nil {
                    let info = categoryTitles[cat] ?? (cat.capitalized, "folder")
                    categoryMap[cat] = (info.0, info.1, [])
                }
                categoryMap[cat]?.entries.append(entry)
            }

            // Also add app's own container from raw (entries without category)
            for dict in raw {
                guard let path = dict["path"] as? String,
                      let label = dict["label"] as? String,
                      dict["category"] == nil else { continue }
                let accessible = (dict["accessible"] as? Bool) ?? false
                let count = (dict["entryCount"] as? Int) ?? 0
                let entry = PathEntry(path: path, label: label, accessible: accessible, entryCount: count)
                if categoryMap["contenedores"] == nil {
                    categoryMap["contenedores"] = ("Contenedores", "shippingbox.fill", [])
                }
                categoryMap["contenedores"]?.entries.append(entry)
            }

            var built: [Section] = []
            for key in categoryOrder {
                if let val = categoryMap[key], !val.entries.isEmpty {
                    built.append(Section(title: val.title, icon: val.icon, entries: val.entries))
                }
            }

            DispatchQueue.main.async {
                guard let self else { return }
                self.sections = built
                self.spinner.stopAnimating()
                self.tableView.reloadData()

                let total = built.reduce(0) { $0 + $1.entries.count }
                let accessible = built.reduce(0) { $0 + $1.entries.filter { $0.accessible }.count }
                self.title = "Sistema (\(accessible)/\(total))"
            }
        }
    }

    // MARK: - DataSource

    override func numberOfSections(in tableView: UITableView) -> Int { sections.count }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        let s = sections[section]
        let accessible = s.entries.filter { $0.accessible }.count
        return "\(s.title) (\(accessible)/\(s.entries.count))"
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        sections[section].entries.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let entry = sections[indexPath.section].entries[indexPath.row]
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = FDTheme.card
        cell.textLabel?.font = FDTheme.controlFont()
        cell.detailTextLabel?.font = FDTheme.monoFont(10)
        cell.detailTextLabel?.lineBreakMode = .byTruncatingMiddle

        if entry.accessible {
            cell.textLabel?.textColor = FDTheme.primaryText
            cell.detailTextLabel?.textColor = FDTheme.tertiaryText
            cell.accessoryType = .disclosureIndicator
            cell.textLabel?.text = "\(entry.label)  (\(entry.entryCount))"
            cell.detailTextLabel?.text = entry.path
            cell.imageView?.image = UIImage(systemName: "folder.fill")
            cell.imageView?.tintColor = FDTheme.accent
        } else {
            cell.textLabel?.textColor = FDTheme.tertiaryText
            cell.detailTextLabel?.textColor = FDTheme.tertiaryText.withAlphaComponent(0.5)
            cell.accessoryType = .none
            cell.textLabel?.text = "\(entry.label)  (bloqueado)"
            cell.detailTextLabel?.text = entry.path
            cell.imageView?.image = UIImage(systemName: "lock.fill")
            cell.imageView?.tintColor = FDTheme.tertiaryText
        }

        return cell
    }

    // MARK: - Delegate

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let entry = sections[indexPath.section].entries[indexPath.row]
        guard entry.accessible else { return }
        let browser = FileBrowserViewController(path: entry.path, title: entry.label)
        navigationController?.pushViewController(browser, animated: true)
    }
}
