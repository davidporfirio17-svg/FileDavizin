import UIKit

final class SettingsViewController: UIViewController {
    private let tableView = UITableView(frame: .zero, style: .insetGrouped)
    private var statusObserver: NSObjectProtocol?

    private struct Row {
        let title: String
        let detail: String
        let icon: String?
        let action: (() -> Void)?
        init(title: String, detail: String, icon: String? = nil, action: (() -> Void)? = nil) {
            self.title = title; self.detail = detail; self.icon = icon; self.action = action
        }
    }

    private var sections: [(title: String, rows: [Row])] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Info"
        view.backgroundColor = FDTheme.background
        setupTableView()
        rebuildData()

        statusObserver = NotificationCenter.default.addObserver(
            forName: SandboxManager.statusDidChange,
            object: nil, queue: .main
        ) { [weak self] _ in
            self?.rebuildData()
        }
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    private func setupTableView() {
        tableView.backgroundColor = .clear
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        tableView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(tableView)
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.topAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
    }

    private func rebuildData() {
        let status = SandboxManager.shared.status

        let deviceRows: [Row] = [
            Row(title: "Dispositivo", detail: FDDeviceInfo.deviceModel),
            Row(title: "iOS", detail: FDDeviceInfo.systemDescription),
            Row(title: "Hardware", detail: FDDeviceInfo.displayMachineName),
            Row(title: "Compatibilidad",
                detail: FDSupportPolicy.isCurrentSystemSupported
                    ? "Compatible (\(FDSupportPolicy.supportedRangesDescription))"
                    : "No compatible"),
        ]

        let escapeLevel = SandboxManager.shared.hasFullEscape
            ? "Jailbreak (root + sandbox escape)"
            : "Parcial (WQ-SYM sandbox extensions)"

        let engineRows: [Row] = [
            Row(title: "Estado", detail: status.displayText),
            Row(title: "Nivel de acceso", detail: escapeLevel,
                icon: SandboxManager.shared.hasFullEscape ? "lock.open.fill" : "lock.fill"),
            Row(title: "UID", detail: "uid=\(getuid()) euid=\(geteuid())",
                icon: getuid() == 0 ? "person.badge.key" : "person"),
            Row(title: "Diagnostico", detail: String(cString: FDLastDiagnostic())),
            Row(title: "Ejecutar diagnostico completo", detail: "Prueba todas las rutas y copia al clipboard", action: { [weak self] in
                self?.runFullDiagnostic()
            }),
        ]

        let goToRow: [Row] = [
            Row(title: "Ir a ruta...", detail: "Escribe cualquier ruta del filesystem", icon: "magnifyingglass", action: { [weak self] in
                self?.promptGoToPath()
            }),
        ]

        let userRows: [Row] = [
            Row(title: "/var/mobile", detail: "Raiz del usuario", icon: "person.fill", action: { [weak self] in
                self?.browsePath("/private/var/mobile", title: "/var/mobile")
            }),
            Row(title: "App Containers", detail: "Datos de aplicaciones", icon: "app.badge", action: { [weak self] in
                self?.browsePath("/private/var/mobile/Containers/Data/Application", title: "App Containers")
            }),
            Row(title: "App Groups", detail: "Grupos compartidos", icon: "square.stack.3d.up", action: { [weak self] in
                self?.browsePath("/private/var/mobile/Containers/Shared/AppGroup", title: "App Groups")
            }),
            Row(title: "Media", detail: "Fotos, musica, videos", icon: "photo.on.rectangle", action: { [weak self] in
                self?.browsePath("/private/var/mobile/Media", title: "Media")
            }),
            Row(title: "Library", detail: "Preferencias y caches del usuario", icon: "books.vertical", action: { [weak self] in
                self?.browsePath("/private/var/mobile/Library", title: "Library")
            }),
            Row(title: "Documents", detail: "Documentos del usuario", icon: "doc.text", action: { [weak self] in
                self?.browsePath("/private/var/mobile/Documents", title: "Documents")
            }),
        ]

        let systemRows: [Row] = [
            Row(title: "/", detail: "Raiz del filesystem", icon: "externaldrive.fill", action: { [weak self] in
                self?.browsePath("/", title: "/")
            }),
            Row(title: "/System/Library", detail: "Frameworks, daemons, plists del sistema", icon: "gearshape.2", action: { [weak self] in
                self?.browsePath("/System/Library", title: "System Library")
            }),
            Row(title: "/usr", detail: "Binarios y librerias del sistema", icon: "terminal", action: { [weak self] in
                self?.browsePath("/usr", title: "/usr")
            }),
            Row(title: "/etc", detail: "Configuracion del sistema", icon: "wrench.and.screwdriver", action: { [weak self] in
                self?.browsePath("/private/etc", title: "/etc")
            }),
            Row(title: "/var", detail: "Datos variables del sistema", icon: "internaldrive", action: { [weak self] in
                self?.browsePath("/private/var", title: "/var")
            }),
            Row(title: "/var/root", detail: "Home de root", icon: "person.badge.key", action: { [weak self] in
                self?.browsePath("/private/var/root", title: "/var/root")
            }),
            Row(title: "/var/db", detail: "Bases de datos del sistema", icon: "cylinder", action: { [weak self] in
                self?.browsePath("/private/var/db", title: "/var/db")
            }),
            Row(title: "/var/logs", detail: "Logs del sistema", icon: "doc.text.magnifyingglass", action: { [weak self] in
                self?.browsePath("/private/var/logs", title: "/var/logs")
            }),
            Row(title: "/var/preferences", detail: "Preferencias globales", icon: "slider.horizontal.3", action: { [weak self] in
                self?.browsePath("/private/var/preferences", title: "Preferences")
            }),
            Row(title: "/var/MobileDevice", detail: "Provisioning profiles, logs", icon: "iphone", action: { [weak self] in
                self?.browsePath("/private/var/MobileDevice", title: "MobileDevice")
            }),
            Row(title: "/var/containers", detail: "Todos los containers del sistema", icon: "shippingbox", action: { [weak self] in
                self?.browsePath("/private/var/containers", title: "Containers")
            }),
            Row(title: "/var/installd", detail: "Estado de instalacion", icon: "arrow.down.app", action: { [weak self] in
                self?.browsePath("/private/var/installd", title: "installd")
            }),
            Row(title: "/Library", detail: "Library del sistema (raiz)", icon: "building.columns", action: { [weak self] in
                self?.browsePath("/Library", title: "/Library")
            }),
        ]

        sections = [
            (title: "Dispositivo", rows: deviceRows),
            (title: "Motor de acceso", rows: engineRows),
            (title: "Ir a ruta", rows: goToRow),
            (title: "Rutas de usuario", rows: userRows),
            (title: "Rutas del sistema (root)", rows: systemRows),
        ]

        tableView.reloadData()
    }

    private func browsePath(_ path: String, title: String) {
        let browser = FileBrowserViewController(path: path, title: title)
        navigationController?.pushViewController(browser, animated: true)
    }

    private func promptGoToPath() {
        let alert = UIAlertController(
            title: "Ir a ruta",
            message: "Escribe la ruta completa del directorio",
            preferredStyle: .alert)
        alert.addTextField { tf in
            tf.placeholder = "/private/var/mobile"
            tf.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
            tf.autocapitalizationType = .none
            tf.autocorrectionType = .no
            tf.keyboardType = .URL
        }
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        alert.addAction(UIAlertAction(title: "Ir", style: .default) { [weak self] _ in
            guard let path = alert.textFields?.first?.text, !path.isEmpty else { return }
            var resolved = path
            if !resolved.hasPrefix("/") { resolved = "/" + resolved }
            let title = (resolved as NSString).lastPathComponent
            self?.browsePath(resolved, title: title.isEmpty ? "/" : title)
        })
        present(alert, animated: true)
    }

    private func runFullDiagnostic() {
        let alert = UIAlertController(title: "Ejecutando diagnostico...", message: nil, preferredStyle: .alert)
        present(alert, animated: true)
        DispatchQueue.global(qos: .userInitiated).async {
            let report = FDRunFullDiagnostic()
            DispatchQueue.main.async { [weak self] in
                alert.dismiss(animated: true) {
                    UIPasteboard.general.string = report
                    let done = UIAlertController(
                        title: "Diagnostico copiado",
                        message: "El reporte fue copiado al clipboard. Pegalo para compartirlo.",
                        preferredStyle: .alert
                    )
                    done.addAction(UIAlertAction(title: "OK", style: .default))
                    self?.present(done, animated: true)
                    self?.rebuildData()
                }
            }
        }
    }
}

extension SettingsViewController: UITableViewDataSource {
    func numberOfSections(in tableView: UITableView) -> Int { sections.count }

    func tableView(_ tv: UITableView, numberOfRowsInSection section: Int) -> Int {
        sections[section].rows.count
    }

    func tableView(_ tv: UITableView, titleForHeaderInSection section: Int) -> String? {
        sections[section].title
    }

    func tableView(_ tv: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tv.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        let row = sections[indexPath.section].rows[indexPath.row]

        var config = cell.defaultContentConfiguration()
        config.text = row.title
        config.textProperties.color = FDTheme.primaryText
        config.textProperties.font = .systemFont(ofSize: 15, weight: .medium)
        config.secondaryText = row.detail
        config.secondaryTextProperties.color = FDTheme.secondaryText
        config.secondaryTextProperties.font = .systemFont(ofSize: 12)
        config.secondaryTextProperties.numberOfLines = 3
        if let iconName = row.icon {
            config.image = UIImage(systemName: iconName)
            config.imageProperties.tintColor = FDTheme.accent
        }
        cell.contentConfiguration = config
        cell.backgroundColor = FDTheme.card
        cell.accessoryType = row.action != nil ? .disclosureIndicator : .none
        cell.selectionStyle = row.action != nil ? .default : .none

        return cell
    }
}

extension SettingsViewController: UITableViewDelegate {
    func tableView(_ tv: UITableView, didSelectRowAt indexPath: IndexPath) {
        tv.deselectRow(at: indexPath, animated: true)
        sections[indexPath.section].rows[indexPath.row].action?()
    }
}
