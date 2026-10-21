import UIKit

/// UI framework decision (floor-dependent, BUILD-MAC.md §1): the
/// libbox floor for this pin is iOS 13.0 — SwiftUI exists there, but
/// its iOS 13 incarnation has no scene lifecycle, no App protocol
/// and several broken navigation primitives; the legacy product's
/// other mobile client (Android) is plain native views too. UIKit
/// everywhere in this tree, for parity and for honest iOS 13
/// support, is the deliberate choice — not a fallback.
@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        let tabs = UITabBarController()
        tabs.viewControllers = [
            UINavigationController(rootViewController: StatusViewController()),
            UINavigationController(rootViewController: ServersViewController()),
            UINavigationController(rootViewController: SettingsViewController()),
        ]
        tabs.viewControllers?[0].tabBarItem = UITabBarItem(title: "Status", image: nil, tag: 0)
        tabs.viewControllers?[1].tabBarItem = UITabBarItem(title: "Servers", image: nil, tag: 1)
        tabs.viewControllers?[2].tabBarItem = UITabBarItem(title: "Settings", image: nil, tag: 2)
        window.rootViewController = tabs
        window.makeKeyAndVisible()
        self.window = window
        return true
    }
}
