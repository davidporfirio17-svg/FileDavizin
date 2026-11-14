import UIKit

final class HexViewController: UIViewController {
    private var data: Data
    private let filePath: String
    private let textView = UITextView()

    init(data: Data, path: String, name: String) {
        self.data = data
        self.filePath = path
        super.init(nibName: nil, bundle: nil)
        title = "HEX — \(name)"
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.04, green: 0.04, blue: 0.06, alpha: 1)

        navigationItem.rightBarButtonItems = [
            UIBarButtonItem(image: UIImage(systemName: "doc.on.doc"),
                            style: .plain, target: self, action: #selector(copyHex)),
            UIBarButtonItem(title: "Parchear", style: .plain,
                            target: self, action: #selector(patchTapped)),
        ]

        textView.isEditable = false
        textView.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
        textView.textColor = UIColor(red: 0.3, green: 0.85, blue: 0.5, alpha: 1)
        textView.backgroundColor = .clear
        textView.textContainerInset = UIEdgeInsets(top: 8, left: 4, bottom: 8, right: 4)
        textView.indicatorStyle = .white
        textView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(textView)
        NSLayoutConstraint.activate([
            textView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            textView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            textView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            textView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        let sizeLabel = UILabel()
        sizeLabel.text = "\(data.count) bytes"
        sizeLabel.font = .monospacedSystemFont(ofSize: 11, weight: .medium)
        sizeLabel.textColor = UIColor.white.withAlphaComponent(0.4)
        sizeLabel.textAlignment = .right
        sizeLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(sizeLabel)
        NSLayoutConstraint.activate([
            sizeLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            sizeLabel.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -8),
        ])

        renderHex()
    }

    private func renderHex() {
        let maxRender = min(data.count, 65536)
        let bytes = [UInt8](data.prefix(maxRender))
        var result = ""
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
        if data.count > maxRender {
            result += "\n... (\(data.count - maxRender) bytes mas no mostrados)"
        }
        textView.text = result
    }

    @objc private func copyHex() {
        UIPasteboard.general.string = textView.text
        showToast("HEX copiado")
    }

    @objc private func patchTapped() {
        let alert = UIAlertController(
            title: "Parchear bytes",
            message: "Ingresa offset (hex) y bytes nuevos (hex)",
            preferredStyle: .alert)
        alert.addTextField { tf in
            tf.placeholder = "Offset (ej: 0x1A3F)"
            tf.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        }
        alert.addTextField { tf in
            tf.placeholder = "Bytes (ej: 90 90 FF)"
            tf.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        }
        alert.addAction(UIAlertAction(title: "Cancelar", style: .cancel))
        alert.addAction(UIAlertAction(title: "Aplicar", style: .destructive) { [weak self] _ in
            guard let self else { return }
            guard let offsetStr = alert.textFields?[0].text,
                  let bytesStr = alert.textFields?[1].text else { return }

            let cleanOffset = offsetStr
                .replacingOccurrences(of: "0x", with: "")
                .replacingOccurrences(of: "0X", with: "")
            guard let offset = UInt64(cleanOffset, radix: 16) else {
                self.showToast("Offset invalido")
                return
            }

            let hexParts = bytesStr.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            var newBytes: [UInt8] = []
            for part in hexParts {
                guard let b = UInt8(part, radix: 16) else {
                    self.showToast("Byte invalido: \(part)")
                    return
                }
                newBytes.append(b)
            }

            guard Int(offset) + newBytes.count <= self.data.count else {
                self.showToast("Fuera de rango")
                return
            }

            for (i, b) in newBytes.enumerated() {
                self.data[Int(offset) + i] = b
            }

            if FileAccessBridge.writeFile(at: self.filePath, data: self.data) {
                self.showToast("Parcheado \(newBytes.count) bytes")
                self.renderHex()
            } else {
                self.showToast("Error al escribir")
            }
        })
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
        label.frame = CGRect(x: view.bounds.midX - 60, y: 80, width: 120, height: 32)
        view.addSubview(label)
        UIView.animate(withDuration: 0.3, delay: 1.0) {
            label.alpha = 0
        } completion: { _ in label.removeFromSuperview() }
    }
}
