import UIKit

final class FileBrowserViewController: UIViewController {
    private let rootPath: String
    private var nodes: [FileNode] = []
    private let tableView = UITableView(frame: .zero, style: .plain)

    init(path: String, title: String) {
        self.rootPath = path
        super.init(nibName: nil, bundle: nil)
        self.title = title
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = FDTheme.background
        setupTableView()
        setupToolbar()
        loadContents()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        navigationController?.setToolbarHidden(false, animated: animated)
    }

    private func setupTableView() {
        tableView.backgroundColor = .clear
        tableView.separatorColor = FDTheme.hairline
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(FileCell.self, forCellReuseIdentifier: FileCell.reuseID)
        tableView.rowHeight = 56
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
    }

    private func setupToolbar() {
        let appearance = UIToolbarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = FDTheme.backgroundRaise
        navigationController?.toolbar.standardAppearance = appearance
        navigationController?.toolbar.scrollEdgeAppearance = appearance
        navigationController?.toolbar.tintColor = FDTheme.accent

        let pathLabel = UIBarButtonItem(
            title: shortenedPath(rootPath), style: .plain, target: nil, action: nil)
        pathLabel.tintColor = FDTheme.tertiaryText
        pathLabel.setTitleTextAttributes([.font: FDTheme.monoFont(11)], for: .normal)
        pathLabel.setTitleTextAttributes([.font: FDTheme.monoFont(11)], for: .disabled)
        pathLabel.isEnabled = false

        toolbarItems = [pathLabel]
    }

    private func shortenedPath(_ path: String) -> String {
        let comps = (path as NSString).pathComponents
        if comps.count > 4 {
            return ".../" + comps.suffix(3).joined(separator: "/")
        }
        return path
    }

    private func loadContents() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let items = FileAccessBridge.listDirectory(at: self.rootPath)
            let sorted = items.sorted { a, b in
                if a.isDirectory != b.isDirectory { return a.isDirectory }
                return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
            }
            DispatchQueue.main.async {
                self.nodes = sorted
                self.tableView.reloadData()
            }
        }
    }

    private func shareFile(at path: String) {
        let url = URL(fileURLWithPath: path)
        let ac = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        ac.popoverPresentationController?.sourceView = view
        present(ac, animated: true)
    }

    private func deleteFile(at indexPath: IndexPath) {
        let node = nodes[indexPath.row]
        let alert = UIAlertController(
            title: "Eliminar",
            message: "Eliminar \"\(node.name)\"?",
            preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        alert.addAction(UIAlertAction(title: "Eliminar", style: .destructive) { [weak self] _ in
            guard let self else { return }
            if FileAccessBridge.deleteItem(at: node.path) {
                self.nodes.remove(at: indexPath.row)
                self.tableView.deleteRows(at: [indexPath], with: .automatic)
            }
        })
        present(alert, animated: true)
    }

    private func copyToDocuments(at path: String, name: String) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let dest = docs.appendingPathComponent(name)
        if FileAccessBridge.copyItem(from: path, to: dest.path) {
            FDLog.success("Copiado a Documents: \(name)")
            let alert = UIAlertController(title: "Copiado", message: "\(name) guardado en Documents.", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default))
            present(alert, animated: true)
        }
    }
}

extension FileBrowserViewController: UITableViewDataSource {
    func tableView(_ tv: UITableView, numberOfRowsInSection section: Int) -> Int { nodes.count }

    func tableView(_ tv: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tv.dequeueReusableCell(withIdentifier: FileCell.reuseID, for: indexPath) as! FileCell
        cell.configure(with: nodes[indexPath.row])
        return cell
    }
}

extension FileBrowserViewController: UITableViewDelegate {
    func tableView(_ tv: UITableView, didSelectRowAt indexPath: IndexPath) {
        tv.deselectRow(at: indexPath, animated: true)
        let node = nodes[indexPath.row]
        if node.isDirectory {
            let child = FileBrowserViewController(path: node.path, title: node.name)
            navigationController?.pushViewController(child, animated: true)
        } else {
            let preview = FilePreviewController(node: node)
            navigationController?.pushViewController(preview, animated: true)
        }
    }

    func tableView(_ tv: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let node = nodes[indexPath.row]

        let share = UIContextualAction(style: .normal, title: "Compartir") { [weak self] _, _, done in
            self?.shareFile(at: node.path)
            done(true)
        }
        share.backgroundColor = FDTheme.accent

        let copy = UIContextualAction(style: .normal, title: "Copiar") { [weak self] _, _, done in
            self?.copyToDocuments(at: node.path, name: node.name)
            done(true)
        }
        copy.backgroundColor = FDTheme.warm

        let delete = UIContextualAction(style: .destructive, title: "Eliminar") { [weak self] _, _, done in
            self?.deleteFile(at: indexPath)
            done(true)
        }

        return UISwipeActionsConfiguration(actions: [delete, share, copy])
    }
}
