import UIKit

final class FilePreviewController: UIViewController {
    private let node: FileNode
    private let scrollView = UIScrollView()
    private let contentStack = UIStackView()
    private var editTextView: UITextView?

    private static let textExts = Set([
        "txt", "json", "xml", "log", "swift", "m", "h", "c", "cpp",
        "js", "ts", "css", "html", "md", "csv", "py", "rb", "sh",
        "yaml", "yml", "toml", "ini", "cfg", "conf", "entitlements"
    ])

    init(node: FileNode) {
        self.node = node
        super.init(nibName: nil, bundle: nil)
        title = node.name
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = FDTheme.background
        setupNavigationBar()
        setupScrollView()
        loadPreview()
    }

    private func setupNavigationBar() {
        var items: [UIBarButtonItem] = []

        items.append(UIBarButtonItem(
            image: UIImage(systemName: "square.and.arrow.up"),
            style: .plain, target: self, action: #selector(shareTapped)))

        if Self.textExts.contains(node.fileExtension) || node.fileExtension == "plist" {
            items.append(UIBarButtonItem(
                image: UIImage(systemName: "pencil.circle"),
                style: .plain, target: self, action: #selector(editTapped)))
        }

        if !node.isDirectory {
            items.append(UIBarButtonItem(
                title: "HEX", style: .plain,
                target: self, action: #selector(hexTapped)))
        }

        navigationItem.rightBarButtonItems = items
    }

    @objc private func shareTapped() {
        let url = URL(fileURLWithPath: node.path)
        let ac = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        ac.popoverPresentationController?.barButtonItem = navigationItem.rightBarButtonItems?.first
        present(ac, animated: true)
    }

    @objc private func editTapped() {
        guard let tv = editTextView else { return }
        if tv.isEditable {
            tv.isEditable = false
            tv.backgroundColor = FDTheme.card
            if let text = tv.text, let data = text.data(using: .utf8) {
                if FileAccessBridge.writeFile(at: node.path, data: data) {
                    showToast("Guardado")
                } else {
                    showToast("Error al guardar")
                }
            }
            if let idx = navigationItem.rightBarButtonItems?.indices.first(where: { navigationItem.rightBarButtonItems?[$0].action == #selector(editTapped) }) {
                navigationItem.rightBarButtonItems?[idx].image = UIImage(systemName: "pencil.circle")
            }
        } else {
            tv.isEditable = true
            tv.backgroundColor = UIColor(red: 0.08, green: 0.08, blue: 0.12, alpha: 1)
            tv.becomeFirstResponder()
            if let idx = navigationItem.rightBarButtonItems?.indices.first(where: { navigationItem.rightBarButtonItems?[$0].action == #selector(editTapped) }) {
                navigationItem.rightBarButtonItems?[idx].image = UIImage(systemName: "checkmark.circle.fill")
            }
        }
    }

    @objc private func hexTapped() {
        guard let data = FileAccessBridge.readFile(at: node.path) else {
            showToast("No se pudo leer")
            return
        }
        let hexVC = HexViewController(data: data, path: node.path, name: node.name)
        navigationController?.pushViewController(hexVC, animated: true)
    }

    private func setupScrollView() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scrollView)
        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        contentStack.axis = .vertical
        contentStack.spacing = 16
        contentStack.translatesAutoresizingMaskIntoConstraints = false
        scrollView.addSubview(contentStack)
        NSLayoutConstraint.activate([
            contentStack.topAnchor.constraint(equalTo: scrollView.topAnchor, constant: 16),
            contentStack.leadingAnchor.constraint(equalTo: scrollView.leadingAnchor, constant: 16),
            contentStack.trailingAnchor.constraint(equalTo: scrollView.trailingAnchor, constant: -16),
            contentStack.bottomAnchor.constraint(equalTo: scrollView.bottomAnchor, constant: -16),
            contentStack.widthAnchor.constraint(equalTo: scrollView.widthAnchor, constant: -32)
        ])
    }

    private func loadPreview() {
        addInfoCard()
        let ext = node.fileExtension
        switch ext {
        case "png", "jpg", "jpeg", "gif", "heic", "webp", "bmp", "tiff":
            addImagePreview()
        case "plist":
            addPlistPreview()
        default:
            if Self.textExts.contains(ext) {
                addTextPreview()
            } else {
                addHexSnippet()
            }
        }
    }

    // MARK: - Info Card

    private func addInfoCard() {
        let card = UIView()
        card.backgroundColor = FDTheme.card
        card.layer.cornerRadius = FDTheme.cardCornerRadius

        let icon = UIImageView(image: UIImage(systemName: node.iconName))
        icon.tintColor = FDTheme.accent
        icon.contentMode = .scaleAspectFit
        icon.translatesAutoresizingMaskIntoConstraints = false

        let nameLabel = UILabel()
        nameLabel.text = node.name
        nameLabel.font = FDTheme.titleFont(18)
        nameLabel.textColor = FDTheme.primaryText
        nameLabel.numberOfLines = 2

        let detailLabel = UILabel()
        var details: [String] = []
        if !node.displaySize.isEmpty { details.append(node.displaySize) }
        if !node.fileExtension.isEmpty { details.append(node.fileExtension.uppercased()) }
        if let date = node.displayDate { details.append(date) }
        detailLabel.text = details.joined(separator: "  ·  ")
        detailLabel.font = FDTheme.bodyFont()
        detailLabel.textColor = FDTheme.secondaryText

        let pathLabel = UILabel()
        pathLabel.text = node.path
        pathLabel.font = FDTheme.monoFont(10)
        pathLabel.textColor = FDTheme.tertiaryText
        pathLabel.numberOfLines = 3

        let stack = UIStackView(arrangedSubviews: [nameLabel, detailLabel, pathLabel])
        stack.axis = .vertical
        stack.spacing = 6

        card.addSubview(icon)
        card.addSubview(stack)
        stack.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            icon.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
            icon.centerYAnchor.constraint(equalTo: card.centerYAnchor),
            icon.widthAnchor.constraint(equalToConstant: 36),
            icon.heightAnchor.constraint(equalToConstant: 36),
            stack.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 14),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
            stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 16),
            stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -16)
        ])
        contentStack.addArrangedSubview(card)
    }

    // MARK: - Previews

    private func addImagePreview() {
        guard let data = FileAccessBridge.readFile(at: node.path),
              let image = UIImage(data: data) else { return }
        let imageView = UIImageView(image: image)
        imageView.contentMode = .scaleAspectFit
        imageView.clipsToBounds = true
        imageView.layer.cornerRadius = FDTheme.controlCornerRadius
        imageView.heightAnchor.constraint(lessThanOrEqualToConstant: 400).isActive = true
        contentStack.addArrangedSubview(imageView)
    }

    private func addTextPreview() {
        guard let data = FileAccessBridge.readFile(at: node.path),
              let text = String(data: data, encoding: .utf8) else { return }
        let textView = UITextView()
        textView.text = String(text.prefix(100_000))
        textView.isEditable = false
        textView.font = FDTheme.monoFont(12)
        textView.textColor = FDTheme.primaryText
        textView.backgroundColor = FDTheme.card
        textView.layer.cornerRadius = FDTheme.controlCornerRadius
        textView.textContainerInset = UIEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        textView.heightAnchor.constraint(greaterThanOrEqualToConstant: 200).isActive = true
        contentStack.addArrangedSubview(textView)
        self.editTextView = textView
    }

    private func addPlistPreview() {
        let _ = FileAccessBridge.grantAccess(path: (node.path as NSString).deletingLastPathComponent)
        if let dict = NSDictionary(contentsOfFile: node.path) {
            let textView = makeTextView()
            var lines: [String] = []
            for key in (dict as! [String: Any]).keys.sorted() {
                let val = dict[key]
                lines.append("\(key): \(String(describing: val ?? "nil"))")
            }
            textView.text = lines.joined(separator: "\n")
            contentStack.addArrangedSubview(textView)
            self.editTextView = textView
        } else if let arr = NSArray(contentsOfFile: node.path) {
            let textView = makeTextView()
            textView.text = arr.description
            contentStack.addArrangedSubview(textView)
        } else {
            addTextPreview()
        }
    }

    private func addHexSnippet() {
        guard let data = FileAccessBridge.readFile(at: node.path) else { return }
        let preview = min(data.count, 512)
        let hex = formatHexDump(data: data.prefix(preview))

        let label = UILabel()
        label.text = "Vista previa (primeros \(preview) bytes de \(data.count))"
        label.font = FDTheme.captionFont()
        label.textColor = FDTheme.secondaryText
        contentStack.addArrangedSubview(label)

        let textView = UITextView()
        textView.text = hex
        textView.isEditable = false
        textView.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
        textView.textColor = FDTheme.primaryText
        textView.backgroundColor = FDTheme.card
        textView.layer.cornerRadius = FDTheme.controlCornerRadius
        textView.textContainerInset = UIEdgeInsets(top: 12, left: 8, bottom: 12, right: 8)
        textView.heightAnchor.constraint(greaterThanOrEqualToConstant: 250).isActive = true
        contentStack.addArrangedSubview(textView)
    }

    private func formatHexDump(data: Data) -> String {
        var result = ""
        let bytes = [UInt8](data)
        for row in stride(from: 0, to: bytes.count, by: 16) {
            let offset = String(format: "%08X", row)
            var hex = ""
            var ascii = ""
            for col in 0..<16 {
                let idx = row + col
                if idx < bytes.count {
                    hex += String(format: "%02X ", bytes[idx])
                    let ch = bytes[idx]
                    ascii += (ch >= 0x20 && ch < 0x7F) ? String(UnicodeScalar(ch)) : "."
                } else {
                    hex += "   "
                    ascii += " "
                }
                if col == 7 { hex += " " }
            }
            result += "\(offset)  \(hex) |\(ascii)|\n"
        }
        return result
    }

    private func makeTextView() -> UITextView {
        let tv = UITextView()
        tv.isEditable = false
        tv.font = FDTheme.monoFont(11)
        tv.textColor = FDTheme.primaryText
        tv.backgroundColor = FDTheme.card
        tv.layer.cornerRadius = FDTheme.controlCornerRadius
        tv.textContainerInset = UIEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        tv.heightAnchor.constraint(greaterThanOrEqualToConstant: 200).isActive = true
        return tv
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
        label.frame = CGRect(x: view.bounds.midX - 60, y: 80, width: 120, height: 32)
        view.addSubview(label)
        UIView.animate(withDuration: 0.3, delay: 1.0) {
            label.alpha = 0
        } completion: { _ in label.removeFromSuperview() }
    }
}
