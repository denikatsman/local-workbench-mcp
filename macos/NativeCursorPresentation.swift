import Foundation

struct NativeCursorGeneration: Equatable {
    let operationID: String
    let nonce: UUID
}
struct NativeCursorTraceSignal {
    let generation: NativeCursorGeneration
    let ticketSerial: UInt64?
    let lookup: UUID?
    let phase: NativeCursorTracePhase
    let requestedPoint: Bool?
    let reason: String?
}

struct NativeCursorTarget: Equatable {
    let app: NativeAppIdentity
    let windowBindingID: String
    let cgWindowID: UInt32
    let bounds: NativeRect
}

struct NativeCursorPresentation: Equatable {
    let target: NativeCursorTarget
    let point: NativePoint
    let generation: NativeCursorGeneration
    var requestedPoint: Bool? = nil
}

struct NativeCursorTicket: Equatable {
    let presentation: NativeCursorPresentation
    let serial: UInt64
    let createdAt: Double
    let expiresAt: Double
}

enum NativeCursorRefusal: String, Error {
    case invalidRequest = "cursor_request_invalid"
    case identityUnknown = "cursor_app_identity_unknown"
    case identityChanged = "cursor_app_identity_changed"
    case bindingUnknown = "cursor_window_binding_unknown"
    case bindingChanged = "cursor_window_binding_changed"
    case targetMissing = "cursor_target_missing"
    case targetChanged = "cursor_target_changed"
    case targetMoved = "cursor_target_moved"
    case targetOffscreen = "cursor_target_offscreen"
    case visibilityUnknown = "cursor_target_visibility_unknown"
    case targetTransparent = "cursor_target_transparent"
    case windowListUnavailable = "cursor_window_list_unavailable"
    case stackLimit = "cursor_window_stack_limit"
    case stackUnknown = "cursor_window_stack_unknown"
    case stackChanged = "cursor_window_stack_changed"
    case occlusionUnknown = "cursor_occlusion_metadata_unknown"
    case occluded = "cursor_target_occluded"
    case screenUnknown = "cursor_screen_coordinates_unknown"
    case expired = "cursor_presentation_expired"
    case lookupTimeout = "cursor_metadata_timeout"
}

struct NativeCursorWindowMetadata: Equatable {
    var id: UInt32?
    var ownerPID: Int32?
    var bounds: NativeRect?
    var level: Int?
    var alpha: Double?
    var onScreen: Bool?
}

struct NativeCursorSnapshot {
    var app: NativeAppIdentity?
    var bindingMatches: Bool?
    var target: NativeCursorWindowMetadata?
    var stack: [NativeCursorWindowMetadata]
    var screenTop: Double?
    var ownOverlayID: UInt32? = nil
    var ownOverlayPID: Int32? = nil
    var failure: NativeCursorRefusal? = nil
}

struct NativeCursorPlan: Equatable {
    let relativeWindowID: UInt32
    let windowLevel: Int
    let glyphCG: NativeRect
    let clipCG: NativeRect
    let panelAppKit: NativeRect
    let glyphInPanel: NativeRect
}

enum NativeCursorEligibility {
    static let maximumStackWindows = 2048
    static let glyphSize = 28.0

    static func validRect(_ r: NativeRect) -> Bool {
        r.finite && (r.x + r.width).isFinite && (r.y + r.height).isFinite
            && r.x + r.width > r.x && r.y + r.height > r.y
    }

    static func plan(_ p: NativeCursorPresentation, _ snapshot: NativeCursorSnapshot) throws -> NativeCursorPlan {
        let target = p.target
        guard target.app.pid > 0, target.app.launchedAt.isFinite, target.app.launchedAt > 0,
              !target.app.bundleID.isEmpty, target.app.bundlePath.hasPrefix("/"), target.app.executable.hasPrefix("/"),
              !target.windowBindingID.isEmpty, target.cgWindowID > 0, validRect(target.bounds),
              p.point.x.isFinite, p.point.y.isFinite, target.bounds.contains(p.point),
              !p.generation.operationID.isEmpty, p.generation.operationID.utf8.count <= 128 else {
            throw NativeCursorRefusal.invalidRequest
        }
        if let failure = snapshot.failure { throw failure }
        guard let app = snapshot.app else { throw NativeCursorRefusal.identityUnknown }
        guard app == target.app else { throw NativeCursorRefusal.identityChanged }
        guard let binding = snapshot.bindingMatches else { throw NativeCursorRefusal.bindingUnknown }
        guard binding else { throw NativeCursorRefusal.bindingChanged }
        guard let current = snapshot.target else { throw NativeCursorRefusal.targetMissing }
        guard current.id == target.cgWindowID, current.ownerPID == app.pid else { throw NativeCursorRefusal.targetChanged }
        guard let bounds = current.bounds, validRect(bounds), bounds == target.bounds else { throw NativeCursorRefusal.targetMoved }
        guard let onScreen = current.onScreen else { throw NativeCursorRefusal.visibilityUnknown }
        guard onScreen else { throw NativeCursorRefusal.targetOffscreen }
        guard let alpha = current.alpha, alpha.isFinite, (0...1).contains(alpha) else { throw NativeCursorRefusal.visibilityUnknown }
        guard alpha > 0 else { throw NativeCursorRefusal.targetTransparent }
        guard let level = current.level else { throw NativeCursorRefusal.stackUnknown }
        guard snapshot.stack.count <= maximumStackWindows else { throw NativeCursorRefusal.stackLimit }
        let indices = snapshot.stack.indices.filter { snapshot.stack[$0].id == target.cgWindowID }
        guard indices.count == 1, let index = indices.first else { throw NativeCursorRefusal.stackUnknown }
        guard snapshot.stack[index] == current else { throw NativeCursorRefusal.stackChanged }
        guard let top = snapshot.screenTop, top.isFinite else { throw NativeCursorRefusal.screenUnknown }

        let glyph = NativeRect(x: p.point.x - 4, y: p.point.y - 4, width: glyphSize, height: glyphSize)
        guard validRect(glyph) else { throw NativeCursorRefusal.invalidRequest }
        let x = max(glyph.x, bounds.x), y = max(glyph.y, bounds.y)
        let clip = NativeRect(x: x, y: y,
            width: min(glyph.x + glyph.width, bounds.x + bounds.width) - x,
            height: min(glyph.y + glyph.height, bounds.y + bounds.height) - y)
        guard validRect(clip) else { throw NativeCursorRefusal.invalidRequest }
        for window in snapshot.stack.prefix(index) {
            if let overlay = snapshot.ownOverlayID, window.id == overlay,
               let own = snapshot.ownOverlayPID, window.ownerPID == own { continue }
            guard let visible = window.onScreen else { throw NativeCursorRefusal.occlusionUnknown }
            if !visible { continue }
            guard let opacity = window.alpha, opacity.isFinite, (0...1).contains(opacity) else { throw NativeCursorRefusal.occlusionUnknown }
            if opacity == 0 { continue }
            guard let other = window.bounds, validRect(other), window.id != nil, window.ownerPID != nil,
                  let otherLevel = window.level else {
                throw NativeCursorRefusal.occlusionUnknown
            }
            // The surface stays at the target's level. Strictly higher-level
            // windows remain above it, so the compositor handles their pixels
            // without promoting the glyph over them. Metadata must still be
            // valid; same/lower-level overlap remains conservative.
            if otherLevel > level { continue }
            if other.x < clip.x + clip.width && clip.x < other.x + other.width
                && other.y < clip.y + clip.height && clip.y < other.y + other.height {
                throw NativeCursorRefusal.occluded
            }
        }
        let panel = NativeRect(x: clip.x, y: top - clip.y - clip.height, width: clip.width, height: clip.height)
        guard validRect(panel) else { throw NativeCursorRefusal.screenUnknown }
        return NativeCursorPlan(relativeWindowID: target.cgWindowID, windowLevel: level, glyphCG: glyph, clipCG: clip,
            panelAppKit: panel,
            glyphInPanel: NativeRect(x: glyph.x - clip.x, y: clip.y + clip.height - glyph.y - glyph.height,
                width: glyphSize, height: glyphSize))
    }
}

// Serialized by the presenter lock. Nonces stop old operations; serials stop
// old frames/hides from erasing a later frame within the same operation.
struct NativeCursorLifecycle {
    private(set) var generation: NativeCursorGeneration?
    private(set) var ticket: NativeCursorTicket?
    private var serial: UInt64 = 0
    static let lifetime = 0.6

    mutating func begin(operationID: String) -> NativeCursorGeneration {
        let next = NativeCursorGeneration(operationID: operationID, nonce: UUID())
        generation = next; ticket = nil
        return next
    }
    mutating func enqueue(_ presentation: NativeCursorPresentation, now: Double) -> NativeCursorTicket? {
        guard presentation.generation == generation, now.isFinite, now >= 0, serial < UInt64.max else { return nil }
        let expiry = now + Self.lifetime
        guard expiry.isFinite else { return nil }
        serial += 1
        let next = NativeCursorTicket(presentation: presentation, serial: serial, createdAt: now, expiresAt: expiry)
        ticket = next; return next
    }
    func isCurrent(_ expected: NativeCursorTicket) -> Bool { ticket == expected && generation == expected.presentation.generation }
    func live(_ expected: NativeCursorTicket, now: Double) -> Bool {
        isCurrent(expected) && now.isFinite && now >= expected.createdAt && now < expected.expiresAt
    }
    mutating func finish(_ expected: NativeCursorTicket) -> Bool {
        guard isCurrent(expected) else { return false }
        ticket = nil; return true
    }
    mutating func invalidate(_ expected: NativeCursorGeneration) -> Bool {
        guard generation == expected else { return false }
        generation = nil; ticket = nil; return true
    }
}
