import UIKit

final class FileBrowserViewController: UIViewController {
    private let rootPath: String
    private var nodes: [FileNode] = []
    private let tableView = UITableView(frame: .zero, style: .plain)
    private let emptyLabel = UILabel()
    private let spinner = UIActivityIndicatorView(style: .medium)
    private let isPickerMode: Bool
    private var pickerCompletion: ((String?) -> Void)?

    private struct FDClipboard {
        enum Operation { case copy, cut }
        static var items: [(path: String, name: String)] = []
        static var operation: Operation = .copy
    }

    init(path: String, title: String, pickerMode: Bool = false, completion: ((String?) -> Void)? = nil) {
        self.rootPath = path
        self.isPickerMode = pickerMode
        self.pickerCompletion = completion
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

    // MARK: - Setup

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
        if isPickerMode {
            navigationItem.rightBarButtonItem = UIBarButtonItem(
                title: "Seleccionar", style: .done,
                target: self, action: #selector(pickerSelectTapped))
            navigationItem.leftBarButtonItem = UIBarButtonItem(
                title: "Cancelar", style: .plain,
                target: self, action: #selector(pickerCancelTapped))
            return
        }

        let addMenu = UIMenu(children: [
            UIAction(title: "Nueva carpeta", image: UIImage(systemName: "folder.badge.plus")) { [weak self] _ in
                self?.createNewFolder()
            },
            UIAction(title: "Pegar (\(FDClipboard.items.count))",
                     image: UIImage(systemName: "doc.on.clipboard"),
                     attributes: FDClipboard.items.isEmpty ? .disabled : []) { [weak self] _ in
                self?.pasteItems()
            },
        ])

        let addBtn = UIBarButtonItem(image: UIImage(systemName: "plus.circle"), menu: addMenu)
        let refreshBtn = UIBarButtonItem(
            image: UIImage(systemName: "arrow.clockwise"),
            style: .plain, target: self, action: #selector(refreshTapped))
        navigationItem.rightBarButtonItems = [addBtn, refreshBtn]
    }

    // MARK: - Actions

    @objc private func pickerSelectTapped() {
        pickerCompletion?(rootPath)
        dismiss(animated: true)
    }

    @objc private func pickerCancelTapped() {
        pickerCompletion?(nil)
        dismiss(animated: true)
    }

    @objc private func refreshTapped() {
        loadContents()
        setupNavButtons()
    }

    private func shortenedPath(_ path: String) -> String {
        let comps = (path as NSString).pathComponents
        if comps.count > 4 {
            return ".../" + comps.suffix(3).joined(separator: "/")
        }
        return path
    }

    // MARK: - Load

    private func loadContents() {
        emptyLabel.text = "Cargando..."
        spinner.startAnimating()
        emptyLabel.isHidden = false

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let _ = FileAccessBridge.grantAccess(path: self.rootPath)
            let items = FileAccessBridge.listDirectory(at: self.rootPath)
            let sorted = items.sorted()
            DispatchQueue.main.async {
                self.nodes = sorted
                self.tableView.reloadData()
                self.spinner.stopAnimating()
                if sorted.isEmpty {
                    self.emptyLabel.text = "Carpeta vacia o sin acceso"
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

    // MARK: - File Operations

    private func createNewFolder() {
        let alert = UIAlertController(title: "Nueva carpeta", message: nil, preferredStyle: .alert)
        alert.addTextField { $0.placeholder = "Nombre de la carpeta" }
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        alert.addAction(UIAlertAction(title: "Crear", style: .default) { [weak self] _ in
            guard let self, let name = alert.textFields?.first?.text, !name.isEmpty else { return }
            let newPath = (self.rootPath as NSString).appendingPathComponent(name)
            if FileAccessBridge.createDirectory(at: newPath) {
                self.loadContents()
            } else {
                self.showError("No se pudo crear la carpeta.")
            }
        })
        present(alert, animated: true)
    }

    private func renameItem(at indexPath: IndexPath) {
        let node = nodes[indexPath.row]
        let alert = UIAlertController(title: "Renombrar", message: nil, preferredStyle: .alert)
        alert.addTextField { $0.text = node.name }
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        alert.addAction(UIAlertAction(title: "Renombrar", style: .default) { [weak self] _ in
            guard let self, let newName = alert.textFields?.first?.text, !newName.isEmpty else { return }
            let dir = (node.path as NSString).deletingLastPathComponent
            let newPath = (dir as NSString).appendingPathComponent(newName)
            if FileAccessBridge.moveItem(from: node.path, to: newPath) {
                self.loadContents()
            } else {
                self.showError("No se pudo renombrar.")
            }
        })
        present(alert, animated: true)
    }

    private func copyToClipboard(node: FileNode) {
        FDClipboard.items = [(path: node.path, name: node.name)]
        FDClipboard.operation = .copy
        showToast("Copiado al portapapeles")
        setupNavButtons()
    }

    private func cutToClipboard(node: FileNode) {
        FDClipboard.items = [(path: node.path, name: node.name)]
        FDClipboard.operation = .cut
        showToast("Cortado al portapapeles")
        setupNavButtons()
    }

    private func pasteItems() {
        guard !FDClipboard.items.isEmpty else { return }
        var success = 0
        for item in FDClipboard.items {
            var finalPath = (rootPath as NSString).appendingPathComponent(item.name)
            var counter = 1
            while FileManager.default.fileExists(atPath: finalPath) {
                let ext = (item.name as NSString).pathExtension
                let base = (item.name as NSString).deletingPathExtension
                if ext.isEmpty {
                    finalPath = (rootPath as NSString).appendingPathComponent("\(base) (\(counter))")
                } else {
                    finalPath = (rootPath as NSString).appendingPathComponent("\(base) (\(counter)).\(ext)")
                }
                counter += 1
            }
            let ok: Bool
            if FDClipboard.operation == .cut {
                ok = FileAccessBridge.moveItem(from: item.path, to: finalPath)
            } else {
                ok = FileAccessBridge.copyItem(from: item.path, to: finalPath)
            }
            if ok { success += 1 }
        }
        if FDClipboard.operation == .cut { FDClipboard.items.removeAll() }
        showToast("\(success) elemento(s) pegados")
        loadContents()
        setupNavButtons()
    }

    private func moveItem(node: FileNode) {
        let picker = FileBrowserViewController(
            path: "/private/var/mobile",
            title: "Mover a...",
            pickerMode: true
        ) { [weak self] destDir in
            guard let self, let destDir else { return }
            let destPath = (destDir as NSString).appendingPathComponent(node.name)
            if FileAccessBridge.moveItem(from: node.path, to: destPath) {
                self.loadContents()
                self.showToast("Movido")
            } else {
                self.showError("No se pudo mover.")
            }
        }
        let nav = UINavigationController(rootViewController: picker)
        present(nav, animated: true)
    }

    private func shareFile(at path: String) {
        FileAccessBridge.shareFile(at: path, from: self)
    }

    private func copyToDocuments(at path: String, name: String) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let dest = docs.appendingPathComponent(name)
        if FileAccessBridge.copyItem(from: path, to: dest.path) {
            let alert = UIAlertController(title: "Copiado", message: "\(name) guardado en Documents.", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default))
            present(alert, animated: true)
        } else {
            showError("No se pudo copiar.")
        }
    }

    private func deleteFile(at indexPath: IndexPath) {
        let node = nodes[indexPath.row]
        let alert = UIAlertController(
            title: "Eliminar",
            message: "\u{00BF}Eliminar \"\(node.name)\"?",
            preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        alert.addAction(UIAlertAction(title: "Eliminar", style: .destructive) { [weak self] _ in
            guard let self else { return }
            if FileAccessBridge.deleteItem(at: node.path) {
                self.nodes.remove(at: indexPath.row)
                self.tableView.deleteRows(at: [indexPath], with: .automatic)
                self.updateCountLabel()
            } else {
                self.showError("No se pudo eliminar.")
            }
        })
        present(alert, animated: true)
    }

    private func showFileInfo(for node: FileNode) {
        var msg = "Ruta: \(node.path)\n"
        msg += "Tamano: \(node.displaySize)\n"
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

    // MARK: - Helpers

    private func showError(_ msg: String) {
        let alert = UIAlertController(title: "Error", message: msg, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }

    private func showToast(_ msg: String) {
        let label = UILabel()
        label.text = msg
        label.font = .systemFont(ofSize: 13, weight: .semibold)
        label.textColor = .white
        label.textAlignment = .center
        label.backgroundColor = FDTheme.accent.withAlphaComponent(0.9)
        label.layer.cornerRadius = 8
        label.clipsToBounds = true
        let width = max(140, msg.count * 9)
        label.frame = CGRect(x: Int(view.bounds.midX) - width / 2, y: 80, width: width, height: 32)
        view.addSubview(label)
        UIView.animate(withDuration: 0.3, delay: 1.0) {
            label.alpha = 0
        } completion: { _ in label.removeFromSuperview() }
    }
}

// MARK: - UITableViewDataSource

extension FileBrowserViewController: UITableViewDataSource {
    func tableView(_ tv: UITableView, numberOfRowsInSection section: Int) -> Int { nodes.count }

    func tableView(_ tv: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tv.dequeueReusableCell(withIdentifier: FileCell.reuseID, for: indexPath) as! FileCell
        cell.configure(with: nodes[indexPath.row])
        return cell
    }
}

// MARK: - UITableViewDelegate

extension FileBrowserViewController: UITableViewDelegate {
    func tableView(_ tv: UITableView, didSelectRowAt indexPath: IndexPath) {
        tv.deselectRow(at: indexPath, animated: true)
        let node = nodes[indexPath.row]
        if isPickerMode {
            if node.isDirectory {
                let child = FileBrowserViewController(
                    path: node.path, title: node.name,
                    pickerMode: true, completion: pickerCompletion)
                navigationController?.pushViewController(child, animated: true)
            }
            return
        }
        if node.isDirectory {
            let child = FileBrowserViewController(path: node.path, title: node.name)
            navigationController?.pushViewController(child, animated: true)
        } else {
            let preview = FilePreviewController(node: node)
            navigationController?.pushViewController(preview, animated: true)
        }
    }

    func tableView(_ tv: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        guard !isPickerMode else { return nil }
        let node = nodes[indexPath.row]

        let delete = UIContextualAction(style: .destructive, title: "Eliminar") { [weak self] _, _, done in
            self?.deleteFile(at: indexPath)
            done(true)
        }

        let more = UIContextualAction(style: .normal, title: "Mas") { [weak self] _, _, done in
            self?.showActionsSheet(for: node, at: indexPath)
            done(true)
        }
        more.backgroundColor = .systemBlue

        let share = UIContextualAction(style: .normal, title: "Compartir") { [weak self] _, _, done in
            self?.shareFile(at: node.path)
            done(true)
        }
        share.backgroundColor = FDTheme.accent

        if node.isDirectory {
            return UISwipeActionsConfiguration(actions: [delete, more])
        }
        return UISwipeActionsConfiguration(actions: [delete, share, more])
    }

    private func showActionsSheet(for node: FileNode, at indexPath: IndexPath) {
        let sheet = UIAlertController(title: node.name, message: nil, preferredStyle: .actionSheet)

        sheet.addAction(UIAlertAction(title: "Copiar", style: .default) { [weak self] _ in
            self?.copyToClipboard(node: node)
        })
        sheet.addAction(UIAlertAction(title: "Cortar", style: .default) { [weak self] _ in
            self?.cutToClipboard(node: node)
        })
        sheet.addAction(UIAlertAction(title: "Renombrar", style: .default) { [weak self] _ in
            self?.renameItem(at: indexPath)
        })
        sheet.addAction(UIAlertAction(title: "Mover a...", style: .default) { [weak self] _ in
            self?.moveItem(node: node)
        })
        sheet.addAction(UIAlertAction(title: "Copiar ruta", style: .default) { _ in
            UIPasteboard.general.string = node.path
        })
        if !node.isDirectory {
            sheet.addAction(UIAlertAction(title: "Compartir", style: .default) { [weak self] _ in
                self?.shareFile(at: node.path)
            })
            sheet.addAction(UIAlertAction(title: "Copiar a Documents", style: .default) { [weak self] _ in
                self?.copyToDocuments(at: node.path, name: node.name)
            })
        }
        sheet.addAction(UIAlertAction(title: "Info", style: .default) { [weak self] _ in
            self?.showFileInfo(for: node)
        })
        sheet.addAction(UIAlertAction(title: "Cancelar", style: .cancel))

        if let popover = sheet.popoverPresentationController {
            popover.sourceView = view
            popover.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 0, height: 0)
        }
        present(sheet, animated: true)
    }

    func tableView(_ tv: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath, point: CGPoint) -> UIContextMenuConfiguration? {
        guard !isPickerMode else { return nil }
        let node = nodes[indexPath.row]
        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            var actions: [UIMenuElement] = []

            actions.append(UIAction(title: "Copiar", image: UIImage(systemName: "doc.on.doc")) { _ in
                self?.copyToClipboard(node: node)
            })
            actions.append(UIAction(title: "Cortar", image: UIImage(systemName: "scissors")) { _ in
                self?.cutToClipboard(node: node)
            })
            actions.append(UIAction(title: "Renombrar", image: UIImage(systemName: "pencil")) { _ in
                self?.renameItem(at: indexPath)
            })
            actions.append(UIAction(title: "Mover a...", image: UIImage(systemName: "folder")) { _ in
                self?.moveItem(node: node)
            })
            actions.append(UIAction(title: "Copiar ruta", image: UIImage(systemName: "link")) { _ in
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

            actions.append(UIAction(title: "Info", image: UIImage(systemName: "info.circle")) { _ in
                self?.showFileInfo(for: node)
            })

            let deleteAction = UIAction(title: "Eliminar", image: UIImage(systemName: "trash"), attributes: .destructive) { _ in
                self?.deleteFile(at: indexPath)
            }

            return UIMenu(children: actions + [deleteAction])
        }
    }
}
