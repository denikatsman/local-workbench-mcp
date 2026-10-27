import Foundation

/// Compare application focus references with references already admitted by the
/// exact window observation. Never inspect an unknown recipient, change focus,
/// send input, or interpret a matching sample as delivery readiness.
enum NativeKeyboardRecipientObservation {
    static let budgetSeconds = 0.05

    static func sample<Element>(window: Element, controls: [(id: String, element: Element)],
        deadline outerDeadline: Double, now: () -> Double, wallNow: () -> Double,
        authorized: () -> Bool, same: (Element, Element) -> Bool,
        read: (_ attribute: String, _ deadline: Double) -> Element?) -> NativeKeyboardRecipientDiagnostic {
        let started = now(), deadline = min(outerDeadline, started + budgetSeconds)
        var failure = "unavailable"
        func result(_ relation: String, controlID: String? = nil) -> NativeKeyboardRecipientDiagnostic {
            let elapsed = now() - started, sampledAt = wallNow()
            return NativeKeyboardRecipientDiagnostic(relation: relation, controlID: controlID,
                sampledAt: sampledAt.isFinite ? sampledAt : nil,
                elapsedSeconds: elapsed.isFinite && elapsed >= 0 ? elapsed : nil,
                budgetSeconds: budgetSeconds)
        }
        func withinBudget() -> Bool {
            let instant = now(), remaining = deadline - instant
            // AX timeouts have millisecond granularity. A positive fraction of
            // one millisecond must not become a zero/unbounded OS timeout.
            return started.isFinite && outerDeadline.isFinite && deadline.isFinite
                && instant.isFinite && instant >= started && remaining >= 0.001
        }
        func admitted() -> Bool {
            guard withinBudget() else { failure = "budget_exhausted"; return false }
            guard authorized() else { failure = "unavailable"; return false }
            guard withinBudget() else { failure = "budget_exhausted"; return false }
            return true
        }
        func reference(_ attribute: String) -> Element? {
            guard admitted() else { return nil }
            let value = read(attribute, deadline)
            guard admitted() else { return nil }
            guard let value = value else { failure = "unavailable"; return nil }
            return value
        }
        guard let firstWindow = reference("AXFocusedWindow") else { return result(failure) }
        if !same(firstWindow, window) {
            // Do not even request a focused-element reference for another window.
            guard let lastWindow = reference("AXFocusedWindow") else { return result(failure) }
            return result(same(firstWindow, lastWindow) ? "other_window" : "changing")
        }
        guard let firstControl = reference("AXFocusedUIElement"),
              let lastWindow = reference("AXFocusedWindow") else { return result(failure) }
        guard same(lastWindow, firstWindow) else { return result("changing") }
        guard let lastControl = reference("AXFocusedUIElement") else { return result(failure) }
        guard same(firstControl, lastControl) else { return result("changing") }
        let matches = controls.filter { same($0.element, firstControl) }
        guard admitted() else { return result(failure) }
        guard matches.count <= 1 else { return result("unavailable") }
        guard let selected = matches.first else { return result("unobserved_control") }
        return result("observed_control", controlID: selected.id)
    }
}
