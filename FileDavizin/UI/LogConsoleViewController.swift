import UIKit

final class LogConsoleViewController: UIViewController {
    private let textView = UITextView()
    private var observer: NSObjectProtocol?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.04, green: 0.04, blue: 0.06, alpha: 1)

        setupHeader()
        setupTextView()
        refreshLog()

        observer = NotificationCenter.default.addObserver(
            forName: FDLogStore.didUpdate, object: nil, queue: .main
        ) { [weak self] _ in
            self?.refreshLog()
        }
    }

    deinit {
        if let o = observer { NotificationCenter.default.removeObserver(o) }
    }

    private func setupHeader() {
        let header = UIView()
        header.backgroundColor = UIColor(red: 0.06, green: 0.06, blue: 0.09, alpha: 1)
        header.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(header)

        let titleLabel = UILabel()
        titleLabel.text = "Consola"
        titleLabel.font = .monospacedSystemFont(ofSize: 15, weight: .bold)
        titleLabel.textColor = UIColor(red: 0.3, green: 0.9, blue: 0.5, alpha: 1)
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(titleLabel)

        let countLabel = UILabel()
        countLabel.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        countLabel.textColor = UIColor.white.withAlphaComponent(0.4)
        countLabel.tag = 100
        countLabel.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(countLabel)

        let closeBtn = UIButton(type: .system)
        closeBtn.setImage(UIImage(systemName: "xmark.circle.fill"), for: .normal)
        closeBtn.tintColor = UIColor.white.withAlphaComponent(0.5)
        closeBtn.addTarget(self, action: #selector(closeTapped), for: .touchUpInside)
        closeBtn.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(closeBtn)

        let copyBtn = UIButton(type: .system)
        copyBtn.setImage(UIImage(systemName: "doc.on.doc"), for: .normal)
        copyBtn.tintColor = UIColor(red: 0.3, green: 0.9, blue: 0.5, alpha: 1)
        copyBtn.addTarget(self, action: #selector(copyTapped), for: .touchUpInside)
        copyBtn.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(copyBtn)

        let clearBtn = UIButton(type: .system)
        clearBtn.setImage(UIImage(systemName: "trash"), for: .normal)
        clearBtn.tintColor = UIColor(red: 0.98, green: 0.4, blue: 0.4, alpha: 1)
        clearBtn.addTarget(self, action: #selector(clearTapped), for: .touchUpInside)
        clearBtn.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(clearBtn)

        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: view.topAnchor),
            header.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            header.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            header.heightAnchor.constraint(equalToConstant: 52),

            titleLabel.leadingAnchor.constraint(equalTo: header.leadingAnchor, constant: 16),
            titleLabel.centerYAnchor.constraint(equalTo: header.centerYAnchor),

            countLabel.leadingAnchor.constraint(equalTo: titleLabel.trailingAnchor, constant: 8),
            countLabel.centerYAnchor.constraint(equalTo: header.centerYAnchor),

            closeBtn.trailingAnchor.constraint(equalTo: header.trailingAnchor, constant: -12),
            closeBtn.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            closeBtn.widthAnchor.constraint(equalToConstant: 36),
            closeBtn.heightAnchor.constraint(equalToConstant: 36),

            copyBtn.trailingAnchor.constraint(equalTo: closeBtn.leadingAnchor, constant: -4),
            copyBtn.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            copyBtn.widthAnchor.constraint(equalToConstant: 36),
            copyBtn.heightAnchor.constraint(equalToConstant: 36),

            clearBtn.trailingAnchor.constraint(equalTo: copyBtn.leadingAnchor, constant: -4),
            clearBtn.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            clearBtn.widthAnchor.constraint(equalToConstant: 36),
            clearBtn.heightAnchor.constraint(equalToConstant: 36),
        ])

        textView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(textView)
        NSLayoutConstraint.activate([
            textView.topAnchor.constraint(equalTo: header.bottomAnchor),
            textView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            textView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            textView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    private func setupTextView() {
        textView.isEditable = false
        textView.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
        textView.textColor = UIColor(red: 0.3, green: 0.9, blue: 0.5, alpha: 1)
        textView.backgroundColor = .clear
        textView.textContainerInset = UIEdgeInsets(top: 8, left: 10, bottom: 8, right: 10)
        textView.indicatorStyle = .white
    }

    private func refreshLog() {
        textView.text = FDLogStore.shared.allText
        if let countLabel = view.viewWithTag(100) as? UILabel {
            countLabel.text = "(\(FDLogStore.shared.count) lineas)"
        }
        if textView.text.count > 0 {
            let bottom = NSMakeRange(textView.text.count - 1, 1)
            textView.scrollRangeToVisible(bottom)
        }
    }

    @objc private func closeTapped() { dismiss(animated: true) }

    @objc private func copyTapped() {
        UIPasteboard.general.string = FDLogStore.shared.allText
        let label = UILabel()
        label.text = "Copiado"
        label.font = .systemFont(ofSize: 13, weight: .semibold)
        label.textColor = .white
        label.backgroundColor = UIColor(red: 0.2, green: 0.7, blue: 0.4, alpha: 0.9)
        label.textAlignment = .center
        label.layer.cornerRadius = 8
        label.clipsToBounds = true
        label.frame = CGRect(x: view.bounds.midX - 50, y: view.safeAreaInsets.top + 60, width: 100, height: 32)
        view.addSubview(label)
        UIView.animate(withDuration: 0.3, delay: 0.8, options: []) {
            label.alpha = 0
        } completion: { _ in label.removeFromSuperview() }
    }

    @objc private func clearTapped() {
        FDLogStore.shared.clear()
    }
}
