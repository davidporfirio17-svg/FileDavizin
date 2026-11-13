import UIKit

final class AppsViewController: UIViewController {
    private var allContainers: [AppContainer] = []
    private var filteredContainers: [AppContainer] = []
    private var collectionView: UICollectionView!
    private let searchBar = UISearchBar()
    private let statusLabel = UILabel()
    private let spinner = UIActivityIndicatorView(style: .medium)
    private var isScanning = false
    private var statusObserver: NSObjectProtocol?

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Apps"
        view.backgroundColor = FDTheme.background
        setupSearchBar()
        setupCollectionView()
        setupStatusBar()

        statusObserver = NotificationCenter.default.addObserver(
            forName: SandboxManager.statusDidChange,
            object: nil, queue: .main
        ) { [weak self] notification in
            guard let status = notification.object as? SandboxStatus,
                  status.isReady else { return }
            self?.scan()
        }

        if SandboxManager.shared.status.isReady {
            scan()
        } else {
            statusLabel.text = "Esperando motor de acceso..."
            spinner.startAnimating()
        }
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    private func setupSearchBar() {
        searchBar.placeholder = "Buscar por bundle ID..."
        searchBar.searchBarStyle = .minimal
        searchBar.tintColor = FDTheme.accent
        searchBar.barTintColor = FDTheme.background
        if let tf = searchBar.searchTextField as? UITextField {
            tf.textColor = FDTheme.primaryText
            tf.backgroundColor = FDTheme.card
        }
        searchBar.delegate = self
        searchBar.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(searchBar)
        NSLayoutConstraint.activate([
            searchBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            searchBar.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 8),
            searchBar.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -8)
        ])
    }

    private func setupCollectionView() {
        let config = UICollectionLayoutListConfiguration(appearance: .plain)
        let layout = UICollectionViewCompositionalLayout.list(using: config)
        collectionView = UICollectionView(frame: .zero, collectionViewLayout: layout)
        collectionView.backgroundColor = .clear
        collectionView.delegate = self
        collectionView.dataSource = self
        collectionView.register(AppCell.self, forCellWithReuseIdentifier: AppCell.reuseID)
        collectionView.translatesAutoresizingMaskIntoConstraints = false
        collectionView.keyboardDismissMode = .onDrag

        let refreshControl = UIRefreshControl()
        refreshControl.tintColor = FDTheme.accent
        refreshControl.addTarget(self, action: #selector(pullToRefresh), for: .valueChanged)
        collectionView.refreshControl = refreshControl

        view.addSubview(collectionView)
        NSLayoutConstraint.activate([
            collectionView.topAnchor.constraint(equalTo: searchBar.bottomAnchor, constant: 4),
            collectionView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            collectionView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            collectionView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
    }

    private func setupStatusBar() {
        statusLabel.font = FDTheme.captionFont()
        statusLabel.textColor = FDTheme.tertiaryText
        statusLabel.textAlignment = .center
        statusLabel.numberOfLines = 0
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(statusLabel)

        spinner.color = FDTheme.accent
        spinner.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(spinner)

        NSLayoutConstraint.activate([
            statusLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            statusLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            statusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 32),
            statusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -32),
            spinner.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            spinner.bottomAnchor.constraint(equalTo: statusLabel.topAnchor, constant: -12)
        ])
    }

    @objc private func pullToRefresh() {
        scan()
    }

    private func scan() {
        guard !isScanning else { return }
        isScanning = true
        statusLabel.text = "Escaneando contenedores..."
        spinner.startAnimating()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let containers = FileAccessBridge.discoverAllContainers()
            DispatchQueue.main.async {
                guard let self else { return }
                self.allContainers = containers.sorted { $0.identifier < $1.identifier }
                self.applyFilter()
                self.isScanning = false
                self.spinner.stopAnimating()
                self.collectionView.refreshControl?.endRefreshing()
                if self.allContainers.isEmpty {
                    self.statusLabel.text = "No se encontraron contenedores.\nAsegúrate de tener apps instaladas\ny desliza hacia abajo para reintentar."
                } else {
                    self.statusLabel.text = nil
                }
                self.updateTitle()
            }
        }
    }

    private func updateTitle() {
        if allContainers.isEmpty {
            title = "Apps"
        } else {
            title = "Apps (\(filteredContainers.count))"
        }
    }

    private func applyFilter() {
        let query = searchBar.text?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
        if query.isEmpty {
            filteredContainers = allContainers
        } else {
            filteredContainers = allContainers.filter {
                $0.identifier.lowercased().contains(query) ||
                $0.displayName.lowercased().contains(query)
            }
        }
        collectionView.reloadData()
        updateTitle()
    }
}

extension AppsViewController: UICollectionViewDataSource {
    func collectionView(_ cv: UICollectionView, numberOfItemsInSection section: Int) -> Int {
        filteredContainers.count
    }

    func collectionView(_ cv: UICollectionView, cellForItemAt indexPath: IndexPath) -> UICollectionViewCell {
        let cell = cv.dequeueReusableCell(withReuseIdentifier: AppCell.reuseID, for: indexPath) as! AppCell
        cell.configure(with: filteredContainers[indexPath.item])
        return cell
    }
}

extension AppsViewController: UICollectionViewDelegate {
    func collectionView(_ cv: UICollectionView, didSelectItemAt indexPath: IndexPath) {
        cv.deselectItem(at: indexPath, animated: true)
        let container = filteredContainers[indexPath.item]
        let browser = FileBrowserViewController(path: container.path, title: container.displayName)
        navigationController?.pushViewController(browser, animated: true)
    }
}

extension AppsViewController: UISearchBarDelegate {
    func searchBar(_ searchBar: UISearchBar, textDidChange searchText: String) {
        applyFilter()
    }

    func searchBarSearchButtonClicked(_ searchBar: UISearchBar) {
        searchBar.resignFirstResponder()
    }
}
