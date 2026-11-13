import UIKit

final class SettingsViewController: UIViewController {
    private let tableView = UITableView(frame: .zero, style: .insetGrouped)
    private var statusObserver: NSObjectProtocol?

    private struct Row {
        let title: String
        let detail: String
        let action: (() -> Void)?
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

        var deviceRows: [Row] = [
            Row(title: "Dispositivo", detail: FDDeviceInfo.deviceModel, action: nil),
            Row(title: "iOS", detail: FDDeviceInfo.systemDescription, action: nil),
            Row(title: "Hardware", detail: FDDeviceInfo.displayMachineName, action: nil),
        ]

        let compatible = FDSupportPolicy.isCurrentSystemSupported
        deviceRows.append(Row(
            title: "Compatibilidad",
            detail: compatible ? "Compatible (\(FDSupportPolicy.supportedRangesDescription))" : "No compatible",
            action: nil
        ))

        let engineRows: [Row] = [
            Row(title: "Estado", detail: status.displayText, action: nil),
            Row(title: "Diagnóstico", detail: String(cString: FDLastDiagnostic()), action: nil),
        ]

        let pathRows: [Row] = [
            Row(title: "/var/mobile", detail: "Raíz del usuario", action: { [weak self] in
                self?.browsePath("/private/var/mobile", title: "/var/mobile")
            }),
            Row(title: "App Containers", detail: "Datos de aplicaciones", action: { [weak self] in
                self?.browsePath("/private/var/mobile/Containers/Data/Application", title: "App Containers")
            }),
            Row(title: "App Groups", detail: "Grupos compartidos", action: { [weak self] in
                self?.browsePath("/private/var/mobile/Containers/Shared/AppGroup", title: "App Groups")
            }),
            Row(title: "Media", detail: "Fotos, música, etc.", action: { [weak self] in
                self?.browsePath("/private/var/mobile/Media", title: "Media")
            }),
            Row(title: "/var/mobile/Library", detail: "Preferencias del sistema", action: { [weak self] in
                self?.browsePath("/private/var/mobile/Library", title: "Library")
            }),
            Row(title: "/var/mobile/Documents", detail: "Documentos del usuario", action: { [weak self] in
                self?.browsePath("/private/var/mobile/Documents", title: "Documents")
            }),
        ]

        sections = [
            (title: "Dispositivo", rows: deviceRows),
            (title: "Motor de acceso", rows: engineRows),
            (title: "Explorar rutas", rows: pathRows),
        ]

        tableView.reloadData()
    }

    private func browsePath(_ path: String, title: String) {
        let browser = FileBrowserViewController(path: path, title: title)
        navigationController?.pushViewController(browser, animated: true)
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
