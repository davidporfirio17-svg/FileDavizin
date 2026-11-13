import UIKit

final class FileBrowserViewController: UIViewController {
    private let rootPath: String
    private var nodes: [FileNode] = []
    private let tableView = UITableView(frame: .zero, style: .plain)
    private let emptyLabel = UILabel()
    private let spinner = UIActivityIndicatorView(style: .medium)

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
        setupEmptyState()
        setupToolbar()
        setupNavButtons()
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

    private func setupEmptyState() {
        emptyLabel.text = "Cargando..."
        emptyLabel.font = FDTheme.captionFont()
        emptyLabel.textColor = FDTheme.tertiaryText
        emptyLabel.textAlignment = .center
        emptyLabel.numberOfLines = 0
        emptyLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(emptyLabel)

        spinner.color = FDTheme.accent
        spinner.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(spinner)

        NSLayoutConstraint.activate([
            emptyLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            emptyLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 32),
            emptyLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -32),
            spinner.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            spinner.bottomAnchor.constraint(equalTo: emptyLabel.topAnchor, constant: -12),
        ])
        spinner.startAnimating()
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

        let countLabel = UIBarButtonItem(
            title: "", style: .plain, target: nil, action: nil)
        countLabel.tintColor = FDTheme.secondaryText
        countLabel.setTitleTextAttributes([.font: FDTheme.captionFont()], for: .normal)
        countLabel.isEnabled = false
        countLabel.tag = 999

        toolbarItems = [
            pathLabel,
            UIBarButtonItem.flexibleSpace(),
            countLabel,
        ]
    }

    private func setupNavButtons() {
        let refreshBtn = UIBarButtonItem(
            image: UIImage(systemName: "arrow.clockwise"),
            style: .plain, target: self, action: #selector(refreshTapped))
        navigationItem.rightBarButtonItem = refreshBtn
    }

    @objc private func refreshTapped() {
        loadContents()
    }

    private func shortenedPath(_ path: String) -> String {
        let comps = (path as NSString).pathComponents
        if comps.count > 4 {
            return ".../" + comps.suffix(3).joined(separator: "/")
        }
        return path
    }

    private func loadContents() {
        emptyLabel.text = "Cargando..."
        spinner.startAnimating()
        emptyLabel.isHidden = false

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }

            // Grant access before listing
            let _ = FileAccessBridge.grantAccess(path: self.rootPath)

            let items = FileAccessBridge.listDirectory(at: self.rootPath)
            let sorted = items.sorted()

            DispatchQueue.main.async {
                self.nodes = sorted
                self.tableView.reloadData()
                self.spinner.stopAnimating()

                if sorted.isEmpty {
                    self.emptyLabel.text = "Carpeta vacía o sin acceso"
                    self.emptyLabel.isHidden = false
                } else {
                    self.emptyLabel.isHidden = true
                }

                self.updateCountLabel()
            }
        }
    }

    private func updateCountLabel() {
        let dirs = nodes.filter { $0.isDirectory }.count
        let files = nodes.count - dirs
        if let countItem = toolbarItems?.first(where: { $0.tag == 999 }) {
            countItem.title = "\(dirs) carpetas, \(files) archivos"
        }
    }

    private func shareFile(at path: String) {
        FileAccessBridge.shareFile(at: path, from: self)
    }

    private func deleteFile(at indexPath: IndexPath) {
        let node = nodes[indexPath.row]
        let alert = UIAlertController(
            title: "Eliminar",
            message: "¿Eliminar \"\(node.name)\"?",
            preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        alert.addAction(UIAlertAction(title: "Eliminar", style: .destructive) { [weak self] _ in
            guard let self else { return }
            if FileAccessBridge.deleteItem(at: node.path) {
                self.nodes.remove(at: indexPath.row)
                self.tableView.deleteRows(at: [indexPath], with: .automatic)
                self.updateCountLabel()
            } else {
                let err = UIAlertController(title: "Error", message: "No se pudo eliminar el archivo.", preferredStyle: .alert)
                err.addAction(UIAlertAction(title: "OK", style: .default))
                self.present(err, animated: true)
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
        } else {
            let alert = UIAlertController(title: "Error", message: "No se pudo copiar el archivo.", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default))
            present(alert, animated: true)
        }
    }

    private func showFileInfo(for node: FileNode) {
        var msg = "Ruta: \(node.path)\n"
        msg += "Tamaño: \(node.displaySize)\n"
        if let date = node.displayDate {
            msg += "Modificado: \(date)\n"
        }
        msg += "Tipo: \(node.isDirectory ? "Carpeta" : node.fileExtension.uppercased())"

        let alert = UIAlertController(title: node.name, message: msg, preferredStyle: .actionSheet)
        alert.addAction(UIAlertAction(title: "Copiar ruta", style: .default) { _ in
            UIPasteboard.general.string = node.path
        })
        if !node.isDirectory {
            alert.addAction(UIAlertAction(title: "Compartir", style: .default) { [weak self] _ in
                self?.shareFile(at: node.path)
            })
            alert.addAction(UIAlertAction(title: "Copiar a Documents", style: .default) { [weak self] _ in
                self?.copyToDocuments(at: node.path, name: node.name)
            })
        }
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        if let popover = alert.popoverPresentationController {
            popover.sourceView = view
            popover.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 0, height: 0)
        }
        present(alert, animated: true)
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

        let info = UIContextualAction(style: .normal, title: "Info") { [weak self] _, _, done in
            self?.showFileInfo(for: node)
            done(true)
        }
        info.backgroundColor = .systemBlue

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

        if node.isDirectory {
            return UISwipeActionsConfiguration(actions: [delete, info])
        }
        return UISwipeActionsConfiguration(actions: [delete, share, copy, info])
    }

    func tableView(_ tv: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath, point: CGPoint) -> UIContextMenuConfiguration? {
        let node = nodes[indexPath.row]
        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            var actions: [UIAction] = []

            actions.append(UIAction(title: "Copiar ruta", image: UIImage(systemName: "doc.on.doc")) { _ in
                UIPasteboard.general.string = node.path
            })

            if !node.isDirectory {
                actions.append(UIAction(title: "Compartir", image: UIImage(systemName: "square.and.arrow.up")) { _ in
                    self?.shareFile(at: node.path)
                })
                actions.append(UIAction(title: "Copiar a Documents", image: UIImage(systemName: "arrow.down.doc")) { _ in
                    self?.copyToDocuments(at: node.path, name: node.name)
                })
            }

            actions.append(UIAction(title: "Eliminar", image: UIImage(systemName: "trash"), attributes: .destructive) { _ in
                self?.deleteFile(at: indexPath)
            })

            return UIMenu(children: actions)
        }
    }
}
