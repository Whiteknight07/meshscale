import AppKit
import MeshscaleCore
import SwiftUI

struct Palette {
    let dark: Bool
    private func pair(_ light: UInt32, _ dark: UInt32) -> Color { Color(hex: self.dark ? dark : light) }
    var surface: Color { pair(0xf7f7f8, 0x292a2d) }
    var inset: Color { pair(0xebecef, 0x35363a) }
    var ink: Color { pair(0x202124, 0xf3f3f5) }
    var secondary: Color { pair(0x62646c, 0xb0b2ba) }
    var action: Color { pair(0x0067cf, 0x75b6ff) }
    var online: Color { pair(0x247044, 0x82c69b) }
    var error: Color { pair(0xb33629, 0xff9d91) }
    var button: Color { pair(0xffffff, 0x44454a) }
    var separator: Color { ink.opacity(0.12) }
}
extension Color {
    init(hex: UInt32) { self.init(.sRGB, red: Double(hex >> 16) / 255, green: Double((hex >> 8) & 255) / 255, blue: Double(hex & 255) / 255, opacity: 1) }
}
@MainActor enum Artwork {
    private static var cache: [String: NSImage] = [:]
    static func image(_ name: String) -> NSImage {
        if let image = cache[name] { return image }
        guard let url = Bundle.module.url(forResource: name, withExtension: "png"), let image = NSImage(contentsOf: url) else { return NSImage() }
        image.isTemplate = true
        if name.hasPrefix("menu-") { image.size = NSSize(width: 18, height: 18) }
        cache[name] = image
        return image
    }
}
struct Icon: View {
    let name: String
    var size: CGFloat = 18
    var body: some View { Image(nsImage: Artwork.image(name)).resizable().interpolation(.high).frame(width: size, height: size).accessibilityHidden(true) }
}
struct UtilityButton: ButtonStyle {
    var palette: Palette
    var primary = false
    var compact = true
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: compact ? 12 : 13, weight: compact ? .regular : .medium))
            .foregroundStyle(primary ? (palette.dark ? Color(hex: 0x152d49) : .white) : palette.ink)
            .padding(.horizontal, compact ? 10 : 13).padding(.vertical, compact ? 4 : 7)
            .frame(minHeight: compact ? 26 : 34)
            .background(configuration.isPressed ? palette.inset : primary ? palette.action : palette.button, in: RoundedRectangle(cornerRadius: 6))
            .overlay { if !primary { RoundedRectangle(cornerRadius: 6).strokeBorder(palette.separator, lineWidth: 1) } }
            .opacity(enabled ? 1 : 0.45)
    }
}
struct QuietButton: ButtonStyle {
    let palette: Palette
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.contentShape(Rectangle())
            .background(configuration.isPressed ? palette.inset : .clear, in: RoundedRectangle(cornerRadius: 4))
            .opacity(enabled ? 1 : 0.45)
    }
}

struct WaitingIndicator: View {
    let palette: Palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        if reduceMotion {
            ZStack {
                Circle().stroke(palette.separator, lineWidth: 2)
                Circle().trim(from: 0, to: 0.5).stroke(palette.secondary, lineWidth: 2).rotationEffect(.degrees(-90))
            }.frame(width: 23, height: 23).accessibilityLabel("Waiting")
        } else { ProgressView().controlSize(.small).frame(width: 23, height: 23).accessibilityLabel("Waiting") }
    }
}

func text(_ value: String, size: CGFloat = 12, height: CGFloat = 16, weight: Font.Weight = .regular) -> some View {
    Text(value).font(.system(size: size, weight: weight)).frame(height: height, alignment: .leading)
}

func deviceIcon(_ device: MeshDevice) -> String {
    if device.isMobile { return "phone" }
    return device.kind == "node" ? "server" : "laptop"
}

func online(_ value: Bool, p: Palette) -> some View {
    HStack(spacing: 5) {
        if value { Circle().fill(p.online).frame(width: 5, height: 5) }
        else { Circle().strokeBorder(p.secondary, lineWidth: 1).frame(width: 6, height: 6) }
        text(value ? "Online" : "Offline", size: 11)
    }.foregroundStyle(value ? p.online : p.secondary)
}
