import UIKit

final class PatchesViewController: UIViewController {
    private let tableView = UITableView(frame: .zero, style: .insetGrouped)
    private var patches: [PatchEntry] = []
    private let patchDir: URL

    struct PatchEntry: Codable {
        let id: String
        let name: String
        let targetPath: String
        let operations: [PatchOp]
        let createdDate: Double

        var displayDate: String {
            let f = DateFormatter()
            f.dateStyle = .short
            f.timeStyle = .short
            return f.string(from: Date(timeIntervalSince1970: createdDate))
        }
    }

    struct PatchOp: Codable {
        let offset: UInt64
        let original: [UInt8]
        let patched: [UInt8]
    }

    override init(nibName: String? = nil, bundle: Bundle? = nil) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        patchDir = docs.appendingPathComponent("FDPatches", isDirectory: true)
        super.init(nibName: nibName, bundle: bundle)
        try? FileManager.default.createDirectory(at: patchDir, withIntermediateDirectories: true)
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Patches"
        view.backgroundColor = FDTheme.background

        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "plus.circle"),
            style: .plain, target: self, action: #selector(createPatch))

        setupTableView()
        loadPatches()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        loadPatches()
    }

    private func setupTableView() {
        tableView.backgroundColor = .clear
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "patch")
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.topAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    // MARK: - Persistence

    private func loadPatches() {
        guard let files = try? FileManager.default.contentsOfDirectory(at: patchDir, includingPropertiesForKeys: nil) else {
            patches = []
            tableView.reloadData()
            return
        }
        patches = files
            .filter { $0.pathExtension == "json" }
            .compactMap { url -> PatchEntry? in
                guard let data = try? Data(contentsOf: url) else { return nil }
                return try? JSONDecoder().decode(PatchEntry.self, from: data)
            }
            .sorted { $0.createdDate > $1.createdDate }
        tableView.reloadData()
    }

    private func savePatch(_ patch: PatchEntry) {
        let url = patchDir.appendingPathComponent("\(patch.id).json")
        if let data = try? JSONEncoder().encode(patch) {
            try? data.write(to: url)
        }
        loadPatches()
    }

    private func deletePatch(_ patch: PatchEntry) {
        let url = patchDir.appendingPathComponent("\(patch.id).json")
        try? FileManager.default.removeItem(at: url)
        loadPatches()
    }

    // MARK: - Create Patch

    @objc private func createPatch() {
        let alert = UIAlertController(
            title: "Nuevo Patch",
            message: "Nombre del patch y ruta del archivo objetivo",
            preferredStyle: .alert)
        alert.addTextField { tf in
            tf.placeholder = "Nombre (ej: NoAds patch)"
        }
        alert.addTextField { tf in
            tf.placeholder = "Ruta del archivo (ej: /var/mobile/...)"
            tf.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
            tf.autocapitalizationType = .none
            tf.autocorrectionType = .no
        }
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        alert.addAction(UIAlertAction(title: "Crear", style: .default) { [weak self] _ in
            guard let name = alert.textFields?[0].text, !name.isEmpty,
                  let path = alert.textFields?[1].text, !path.isEmpty else { return }
            let patch = PatchEntry(
                id: UUID().uuidString,
                name: name,
                targetPath: path,
                operations: [],
                createdDate: Date().timeIntervalSince1970)
            self?.savePatch(patch)
            self?.editPatch(patch)
        })
        present(alert, animated: true)
    }

    private func editPatch(_ patch: PatchEntry) {
        let editor = PatchEditorViewController(patch: patch, patchDir: patchDir) { [weak self] updated in
            self?.savePatch(updated)
        }
        navigationController?.pushViewController(editor, animated: true)
    }

    private func applyPatch(_ patch: PatchEntry) {
        guard !patch.operations.isEmpty else {
            showAlert("Sin operaciones", "Este patch no tiene operaciones definidas.")
            return
        }

        let _ = FileAccessBridge.grantAccess(path: patch.targetPath)
        let dir = (patch.targetPath as NSString).deletingLastPathComponent
        let _ = FileAccessBridge.grantAccess(path: dir)

        guard var data = FileAccessBridge.readFile(at: patch.targetPath) else {
            showAlert("Error", "No se pudo leer el archivo: \(patch.targetPath)")
            return
        }

        var applied = 0
        for op in patch.operations {
            let offset = Int(op.offset)
            guard offset + op.patched.count <= data.count else { continue }

            var matches = true
            if !op.original.isEmpty {
                for (i, b) in op.original.enumerated() {
                    if data[offset + i] != b { matches = false; break }
                }
            }

            if matches || op.original.isEmpty {
                for (i, b) in op.patched.enumerated() {
                    data[offset + i] = b
                }
                applied += 1
            }
        }

        if FileAccessBridge.writeFile(at: patch.targetPath, data: data) {
            showAlert("Aplicado", "\(applied)/\(patch.operations.count) operaciones aplicadas en \((patch.targetPath as NSString).lastPathComponent)")
        } else {
            showAlert("Error", "No se pudo escribir el archivo.")
        }
    }

    private func sharePatch(_ patch: PatchEntry) {
        let url = patchDir.appendingPathComponent("\(patch.id).json")
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        let ac = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        if let popover = ac.popoverPresentationController {
            popover.sourceView = view
            popover.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 0, height: 0)
        }
        present(ac, animated: true)
    }

    private func importPatch() {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.json])
        picker.delegate = self
        present(picker, animated: true)
    }

    private func showAlert(_ title: String, _ message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
}

// MARK: - TableView

extension PatchesViewController: UITableViewDataSource, UITableViewDelegate {
    func numberOfSections(in tableView: UITableView) -> Int { 2 }

    func tableView(_ tv: UITableView, numberOfRowsInSection section: Int) -> Int {
        section == 0 ? 1 : patches.count
    }

    func tableView(_ tv: UITableView, titleForHeaderInSection section: Int) -> String? {
        section == 0 ? "Acciones" : "Patches guardados (\(patches.count))"
    }

    func tableView(_ tv: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tv.dequeueReusableCell(withIdentifier: "patch", for: indexPath)
        var config = cell.defaultContentConfiguration()

        if indexPath.section == 0 {
            config.text = "Importar patch (.json)"
            config.image = UIImage(systemName: "square.and.arrow.down")
            config.imageProperties.tintColor = FDTheme.accent
            config.textProperties.color = FDTheme.accent
        } else {
            let patch = patches[indexPath.row]
            config.text = patch.name
            config.textProperties.color = FDTheme.primaryText
            config.textProperties.font = .systemFont(ofSize: 15, weight: .medium)
            config.secondaryText = "\(patch.operations.count) ops  \(patch.displayDate)\n\((patch.targetPath as NSString).lastPathComponent)"
            config.secondaryTextProperties.color = FDTheme.secondaryText
            config.secondaryTextProperties.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            config.secondaryTextProperties.numberOfLines = 2
            config.image = UIImage(systemName: "bandage")
            config.imageProperties.tintColor = FDTheme.warm
            cell.accessoryType = .disclosureIndicator
        }

        cell.contentConfiguration = config
        cell.backgroundColor = FDTheme.card
        return cell
    }

    func tableView(_ tv: UITableView, didSelectRowAt indexPath: IndexPath) {
        tv.deselectRow(at: indexPath, animated: true)
        if indexPath.section == 0 {
            importPatch()
            return
        }
        let patch = patches[indexPath.row]
        let sheet = UIAlertController(title: patch.name, message: "\(patch.operations.count) operaciones", preferredStyle: .actionSheet)
        sheet.addAction(UIAlertAction(title: "Editar", style: .default) { [weak self] _ in
            self?.editPatch(patch)
        })
        sheet.addAction(UIAlertAction(title: "Aplicar patch", style: .default) { [weak self] _ in
            self?.applyPatch(patch)
        })
        sheet.addAction(UIAlertAction(title: "Compartir (.json)", style: .default) { [weak self] _ in
            self?.sharePatch(patch)
        })
        sheet.addAction(UIAlertAction(title: "Eliminar", style: .destructive) { [weak self] _ in
            self?.deletePatch(patch)
        })
        sheet.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        if let popover = sheet.popoverPresentationController {
            popover.sourceView = view
            popover.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 0, height: 0)
        }
        present(sheet, animated: true)
    }

    func tableView(_ tv: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        guard indexPath.section == 1 else { return nil }
        let patch = patches[indexPath.row]
        let delete = UIContextualAction(style: .destructive, title: "Eliminar") { [weak self] _, _, done in
            self?.deletePatch(patch)
            done(true)
        }
        let apply = UIContextualAction(style: .normal, title: "Aplicar") { [weak self] _, _, done in
            self?.applyPatch(patch)
            done(true)
        }
        apply.backgroundColor = .systemGreen
        return UISwipeActionsConfiguration(actions: [delete, apply])
    }
}

// MARK: - Document Picker

extension PatchesViewController: UIDocumentPickerDelegate {
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        for url in urls {
            guard url.startAccessingSecurityScopedResource() else { continue }
            defer { url.stopAccessingSecurityScopedResource() }
            guard let data = try? Data(contentsOf: url),
                  let patch = try? JSONDecoder().decode(PatchEntry.self, from: data) else {
                showAlert("Error", "No se pudo leer el patch: \(url.lastPathComponent)")
                continue
            }
            let newPatch = PatchEntry(
                id: UUID().uuidString,
                name: patch.name,
                targetPath: patch.targetPath,
                operations: patch.operations,
                createdDate: Date().timeIntervalSince1970)
            savePatch(newPatch)
        }
    }
}

// MARK: - Patch Editor

final class PatchEditorViewController: UIViewController {
    private var patch: PatchesViewController.PatchEntry
    private let patchDir: URL
    private let onSave: (PatchesViewController.PatchEntry) -> Void
    private let tableView = UITableView(frame: .zero, style: .insetGrouped)
    private var ops: [PatchesViewController.PatchOp]

    init(patch: PatchesViewController.PatchEntry, patchDir: URL, onSave: @escaping (PatchesViewController.PatchEntry) -> Void) {
        self.patch = patch
        self.patchDir = patchDir
        self.onSave = onSave
        self.ops = patch.operations
        super.init(nibName: nil, bundle: nil)
        title = patch.name
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = FDTheme.background

        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "plus.circle"),
            style: .plain, target: self, action: #selector(addOperation))

        tableView.backgroundColor = .clear
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "op")
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.topAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        saveCurrent()
    }

    private func saveCurrent() {
        let updated = PatchesViewController.PatchEntry(
            id: patch.id,
            name: patch.name,
            targetPath: patch.targetPath,
            operations: ops,
            createdDate: patch.createdDate)
        onSave(updated)
    }

    @objc private func addOperation() {
        let alert = UIAlertController(
            title: "Nueva operacion",
            message: "Offset (hex), bytes originales (hex, opcional) y bytes nuevos (hex)",
            preferredStyle: .alert)
        alert.addTextField { tf in
            tf.placeholder = "Offset (ej: 0x1A3F)"
            tf.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        }
        alert.addTextField { tf in
            tf.placeholder = "Original (ej: 90 90 FF) - opcional"
            tf.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        }
        alert.addTextField { tf in
            tf.placeholder = "Nuevo (ej: 00 00 00)"
            tf.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        }
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        alert.addAction(UIAlertAction(title: "Agregar", style: .default) { [weak self] _ in
            guard let self else { return }
            let offsetStr = (alert.textFields?[0].text ?? "")
                .replacingOccurrences(of: "0x", with: "")
                .replacingOccurrences(of: "0X", with: "")
            guard let offset = UInt64(offsetStr, radix: 16) else {
                self.showToast("Offset invalido")
                return
            }
            let origBytes = self.parseHexBytes(alert.textFields?[1].text ?? "")
            guard let newBytes = self.parseHexBytesStrict(alert.textFields?[2].text ?? ""),
                  !newBytes.isEmpty else {
                self.showToast("Bytes nuevos invalidos")
                return
            }
            let op = PatchesViewController.PatchOp(offset: offset, original: origBytes ?? [], patched: newBytes)
            self.ops.append(op)
            self.tableView.reloadData()
            self.saveCurrent()
        })
        present(alert, animated: true)
    }

    private func parseHexBytes(_ str: String) -> [UInt8]? {
        let parts = str.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
        if parts.isEmpty { return [] }
        var result: [UInt8] = []
        for p in parts {
            guard let b = UInt8(p, radix: 16) else { return nil }
            result.append(b)
        }
        return result
    }

    private func parseHexBytesStrict(_ str: String) -> [UInt8]? {
        let parts = str.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
        if parts.isEmpty { return nil }
        var result: [UInt8] = []
        for p in parts {
            guard let b = UInt8(p, radix: 16) else { return nil }
            result.append(b)
        }
        return result
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
        label.frame = CGRect(x: view.bounds.midX - 70, y: 80, width: 140, height: 32)
        view.addSubview(label)
        UIView.animate(withDuration: 0.3, delay: 1.0) {
            label.alpha = 0
        } completion: { _ in label.removeFromSuperview() }
    }
}

extension PatchEditorViewController: UITableViewDataSource, UITableViewDelegate {
    func numberOfSections(in tableView: UITableView) -> Int { 2 }

    func tableView(_ tv: UITableView, numberOfRowsInSection section: Int) -> Int {
        section == 0 ? 1 : ops.count
    }

    func tableView(_ tv: UITableView, titleForHeaderInSection section: Int) -> String? {
        section == 0 ? "Archivo objetivo" : "Operaciones (\(ops.count))"
    }

    func tableView(_ tv: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tv.dequeueReusableCell(withIdentifier: "op", for: indexPath)
        var config = cell.defaultContentConfiguration()

        if indexPath.section == 0 {
            config.text = (patch.targetPath as NSString).lastPathComponent
            config.secondaryText = patch.targetPath
            config.secondaryTextProperties.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
            config.secondaryTextProperties.color = FDTheme.secondaryText
            config.secondaryTextProperties.numberOfLines = 2
            config.image = UIImage(systemName: "doc")
            config.imageProperties.tintColor = FDTheme.accent
        } else {
            let op = ops[indexPath.row]
            let offsetHex = String(format: "0x%X", op.offset)
            let patchedHex = op.patched.map { String(format: "%02X", $0) }.joined(separator: " ")
            config.text = "\(offsetHex) -> \(patchedHex)"
            config.textProperties.font = .monospacedSystemFont(ofSize: 13, weight: .medium)
            config.textProperties.color = FDTheme.primaryText
            if !op.original.isEmpty {
                let origHex = op.original.map { String(format: "%02X", $0) }.joined(separator: " ")
                config.secondaryText = "Original: \(origHex)"
            } else {
                config.secondaryText = "Sin verificacion de original"
            }
            config.secondaryTextProperties.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
            config.secondaryTextProperties.color = FDTheme.tertiaryText
            config.image = UIImage(systemName: "wrench.and.screwdriver")
            config.imageProperties.tintColor = FDTheme.warm
        }

        cell.contentConfiguration = config
        cell.backgroundColor = FDTheme.card
        return cell
    }

    func tableView(_ tv: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        guard indexPath.section == 1 else { return nil }
        let delete = UIContextualAction(style: .destructive, title: "Eliminar") { [weak self] _, _, done in
            self?.ops.remove(at: indexPath.row)
            tv.deleteRows(at: [indexPath], with: .automatic)
            self?.saveCurrent()
            done(true)
        }
        return UISwipeActionsConfiguration(actions: [delete])
    }
}
