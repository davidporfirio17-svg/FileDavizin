import UIKit

final class MainViewController: UIViewController {
    private let appsVC = AppsViewController()
    private let systemVC = FileBrowserViewController(
        path: "/private/var/mobile",
        title: "Sistema")
    private let settingsVC = SettingsViewController()

    private let containerView = UIView()
    private let bottomBar = UIView()
    private let appsButton = UIButton(type: .system)
    private let systemButton = UIButton(type: .system)
    private let settingsButton = UIButton(type: .system)
    private let indicator = UIView()

    private let statusBanner = UILabel()
    private var statusBannerHeight: NSLayoutConstraint!

    private var currentChild: UIViewController?
    private var selectedIndex = 0
    private var statusObserver: NSObjectProtocol?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = FDTheme.background
        setupStatusBanner()
        setupBottomBar()
        setupContainer()
        selectTab(0, animated: false)

        statusObserver = NotificationCenter.default.addObserver(
            forName: SandboxManager.statusDidChange,
            object: nil, queue: .main
        ) { [weak self] notification in
            guard let status = notification.object as? SandboxStatus else { return }
            self?.updateBanner(status)
        }

        SandboxManager.shared.prepareAccess()
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    private func setupStatusBanner() {
        statusBanner.text = "Preparando acceso al sistema..."
        statusBanner.textAlignment = .center
        statusBanner.font = .systemFont(ofSize: 12, weight: .semibold)
        statusBanner.textColor = .white
        statusBanner.backgroundColor = FDTheme.accent.withAlphaComponent(0.9)
        statusBanner.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(statusBanner)

        statusBannerHeight = statusBanner.heightAnchor.constraint(equalToConstant: 28)
        NSLayoutConstraint.activate([
            statusBanner.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            statusBanner.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            statusBanner.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            statusBannerHeight,
        ])
    }

    private func updateBanner(_ status: SandboxStatus) {
        switch status {
        case .idle, .initializing:
            statusBanner.text = "Preparando acceso al sistema..."
            statusBanner.backgroundColor = FDTheme.accent.withAlphaComponent(0.9)
            statusBannerHeight.constant = 28
        case .ready(let method):
            statusBanner.text = "Acceso activo — \(method)"
            statusBanner.backgroundColor = UIColor.systemGreen.withAlphaComponent(0.85)
            UIView.animate(withDuration: 2.0, delay: 1.5) {
                self.statusBannerHeight.constant = 0
                self.statusBanner.alpha = 0
                self.view.layoutIfNeeded()
            }
        case .failed(let msg):
            statusBanner.text = "Error: \(msg)"
            statusBanner.backgroundColor = UIColor.systemRed.withAlphaComponent(0.85)
            statusBannerHeight.constant = 28
        }
    }

    private func setupContainer() {
        containerView.translatesAutoresizingMaskIntoConstraints = false
        view.insertSubview(containerView, at: 0)
        NSLayoutConstraint.activate([
            containerView.topAnchor.constraint(equalTo: view.topAnchor),
            containerView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            containerView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            containerView.bottomAnchor.constraint(equalTo: bottomBar.topAnchor)
        ])
    }

    private func setupBottomBar() {
        bottomBar.backgroundColor = FDTheme.backgroundRaise
        bottomBar.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(bottomBar)

        let separator = UIView()
        separator.backgroundColor = FDTheme.hairline
        separator.translatesAutoresizingMaskIntoConstraints = false
        bottomBar.addSubview(separator)

        configureTabButton(appsButton, title: "Apps", icon: "square.grid.2x2", tag: 0)
        configureTabButton(systemButton, title: "Sistema", icon: "folder", tag: 1)
        configureTabButton(settingsButton, title: "Info", icon: "gear", tag: 2)

        let stack = UIStackView(arrangedSubviews: [appsButton, systemButton, settingsButton])
        stack.axis = .horizontal
        stack.distribution = .fillEqually
        stack.translatesAutoresizingMaskIntoConstraints = false
        bottomBar.addSubview(stack)

        indicator.backgroundColor = FDTheme.accent
        indicator.layer.cornerRadius = 1.5
        indicator.translatesAutoresizingMaskIntoConstraints = false
        bottomBar.addSubview(indicator)

        NSLayoutConstraint.activate([
            bottomBar.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            bottomBar.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            bottomBar.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            bottomBar.heightAnchor.constraint(equalToConstant: 84),

            separator.topAnchor.constraint(equalTo: bottomBar.topAnchor),
            separator.leadingAnchor.constraint(equalTo: bottomBar.leadingAnchor),
            separator.trailingAnchor.constraint(equalTo: bottomBar.trailingAnchor),
            separator.heightAnchor.constraint(equalToConstant: 0.5),

            stack.topAnchor.constraint(equalTo: bottomBar.topAnchor, constant: 6),
            stack.leadingAnchor.constraint(equalTo: bottomBar.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: bottomBar.trailingAnchor),
            stack.heightAnchor.constraint(equalToConstant: 52),

            indicator.heightAnchor.constraint(equalToConstant: 3),
            indicator.widthAnchor.constraint(equalToConstant: 40),
            indicator.topAnchor.constraint(equalTo: bottomBar.topAnchor),
            indicator.centerXAnchor.constraint(equalTo: appsButton.centerXAnchor)
        ])
    }

    private func configureTabButton(_ button: UIButton, title: String, icon: String, tag: Int) {
        var config = UIButton.Configuration.plain()
        config.image = UIImage(systemName: icon)?.withConfiguration(
            UIImage.SymbolConfiguration(pointSize: 20, weight: .medium))
        config.title = title
        config.imagePlacement = .top
        config.imagePadding = 4
        config.baseForegroundColor = FDTheme.tertiaryText
        let font = UIFont.systemFont(ofSize: 10, weight: .semibold)
        config.titleTextAttributesTransformer = .init { var a = $0; a.font = font; return a }
        button.configuration = config
        button.tag = tag
        button.addTarget(self, action: #selector(tabTapped(_:)), for: .touchUpInside)
    }

    @objc private func tabTapped(_ sender: UIButton) {
        selectTab(sender.tag, animated: true)
    }

    private func selectTab(_ index: Int, animated: Bool) {
        selectedIndex = index

        let controllers: [UIViewController] = [appsVC, systemVC, settingsVC]
        let target = controllers[index]
        let targetNav = UINavigationController(rootViewController: target)
        targetNav.navigationBar.prefersLargeTitles = false
        targetNav.navigationBar.barTintColor = FDTheme.background
        targetNav.navigationBar.tintColor = FDTheme.accent
        let appearance = UINavigationBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = FDTheme.background
        appearance.titleTextAttributes = [.foregroundColor: FDTheme.primaryText]
        targetNav.navigationBar.standardAppearance = appearance
        targetNav.navigationBar.scrollEdgeAppearance = appearance

        if let old = currentChild {
            old.willMove(toParent: nil)
            old.view.removeFromSuperview()
            old.removeFromParent()
        }

        addChild(targetNav)
        targetNav.view.frame = containerView.bounds
        targetNav.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        containerView.addSubview(targetNav.view)
        targetNav.didMove(toParent: self)
        currentChild = targetNav

        let buttons = [appsButton, systemButton, settingsButton]
        for (i, btn) in buttons.enumerated() {
            btn.configuration?.baseForegroundColor = i == index ? FDTheme.accent : FDTheme.tertiaryText
        }

        let anchor = buttons[index]
        let duration = animated ? 0.25 : 0
        UIView.animate(withDuration: duration, delay: 0, options: .curveEaseOut) {
            self.indicator.center.x = anchor.center.x
        }
    }
}
