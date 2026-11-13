import UIKit

final class FilePreviewController: UIViewController {
    private let node: FileNode
    private let scrollView = UIScrollView()
    private let contentStack = UIStackView()

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
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "square.and.arrow.up"),
            style: .plain, target: self, action: #selector(shareTapped))
    }

    @objc private func shareTapped() {
        let url = URL(fileURLWithPath: node.path)
        let ac = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        ac.popoverPresentationController?.barButtonItem = navigationItem.rightBarButtonItem
        present(ac, animated: true)
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

        switch node.fileExtension {
        case "png", "jpg", "jpeg", "gif", "heic", "webp", "bmp", "tiff":
            addImagePreview()
        case "plist":
            addPlistPreview()
        case "txt", "json", "xml", "log", "swift", "m", "h", "c", "cpp",
             "js", "ts", "css", "html", "md", "csv", "py", "rb", "sh":
            addTextPreview()
        default:
            break
        }
    }

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
        icon.translatesAutoresizingMaskIntoConstraints = false
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

    private func addImagePreview() {
        guard let image = UIImage(contentsOfFile: node.path) else { return }
        let imageView = UIImageView(image: image)
        imageView.contentMode = .scaleAspectFit
        imageView.clipsToBounds = true
        imageView.layer.cornerRadius = FDTheme.controlCornerRadius
        imageView.heightAnchor.constraint(lessThanOrEqualToConstant: 400).isActive = true
        contentStack.addArrangedSubview(imageView)
    }

    private func addTextPreview() {
        guard let data = FileManager.default.contents(atPath: node.path),
              let text = String(data: data, encoding: .utf8) else { return }
        let textView = UITextView()
        textView.text = String(text.prefix(50_000))
        textView.isEditable = false
        textView.font = FDTheme.monoFont(12)
        textView.textColor = FDTheme.primaryText
        textView.backgroundColor = FDTheme.card
        textView.layer.cornerRadius = FDTheme.controlCornerRadius
        textView.textContainerInset = UIEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        textView.heightAnchor.constraint(greaterThanOrEqualToConstant: 200).isActive = true
        contentStack.addArrangedSubview(textView)
    }

    private func addPlistPreview() {
        if let dict = NSDictionary(contentsOfFile: node.path) {
            addFormattedDictPreview(dict as! [String: Any])
        } else if let arr = NSArray(contentsOfFile: node.path) {
            let textView = makeTextView()
            textView.text = arr.description
            contentStack.addArrangedSubview(textView)
        } else {
            addTextPreview()
        }
    }

    private func addFormattedDictPreview(_ dict: [String: Any]) {
        let textView = makeTextView()
        var lines: [String] = []
        for key in dict.keys.sorted() {
            let val = dict[key]
            lines.append("\(key): \(String(describing: val ?? "nil"))")
        }
        textView.text = lines.joined(separator: "\n")
        contentStack.addArrangedSubview(textView)
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
}
