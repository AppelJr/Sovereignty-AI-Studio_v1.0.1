// SovereigntyAPIClient.swift
// SovereigntyGuard
//
// Local-first device client for Sovereignty AI Studio / DevAssist420.
// Control-plane traffic uses the loopback DevAssist bridge on port 9899.

import Foundation
#if canImport(UIKit)
import UIKit
#endif

public final class SovereigntyAPIClient: @unchecked Sendable {
    public static let shared = SovereigntyAPIClient()

    public var baseURL: String {
        get { _baseURL }
        set { _baseURL = newValue }
    }
    private var _baseURL: String
    public var authToken: String?
    private let session: URLSession

    public init(baseURL: String = "http://127.0.0.1:9899") {
        self._baseURL = baseURL
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        self.session = URLSession(configuration: config)
    }

    // MARK: - DevAssist420 device bridge

    /// Returns the same role/agreement state exposed by the local DevAssist bridge.
    public func devAssistAgreement() async throws -> [String: Any] {
        let data = try await get(path: "/api/devassist/agreement")
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw APIError.invalidResponse
        }
        return json
    }

    /// Send device/voice text through the single governed DevAssist entry point.
    /// The bridge performs canonical-state, identity, policy, routing, inference and SCAR checks.
    public func sendToDevAssist(text: String,
                                action: String = "chat",
                                requesterID: String? = nil,
                                prefer: String = "local") async throws -> [String: Any] {
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw APIError.invalidRequest
        }
        var body: [String: Any] = [
            "text": text,
            "action": action,
            "prefer": prefer,
            "context": ["source": "ios-device"]
        ]
        if let requesterID { body["requester_id"] = requesterID }

        let data = try await post(path: "/api/v1/shortcut/route", body: body)
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw APIError.invalidResponse
        }
        return json
    }

    // MARK: - Existing status surface

    public func healthCheck() async throws -> Bool {
        let data = try await get(path: "/health")
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let status = json["status"] as? String {
            return status == "ok" || status == "healthy"
        }
        return false
    }

    public func mobileStatus() async throws -> [String: Any] {
        let data = try await get(path: "/api/v1/mobile/status")
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw APIError.invalidResponse
        }
        return json
    }

    public func login(username: String, password: String) async throws -> String {
        let body: [String: Any] = ["username": username, "password": password]
        let data = try await post(path: "/api/v1/auth/login", body: body)
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = json["access_token"] as? String else {
            throw APIError.authenticationFailed
        }
        self.authToken = token
        return token
    }

    public func getAlerts(limit: Int = 50) async throws -> [[String: Any]] {
        let data = try await get(path: "/api/v1/alerts/?limit=\(limit)")
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw APIError.invalidResponse
        }
        return json
    }

    public func createAlert(type: String, title: String, message: String,
                            severity: String = "medium", speak: Bool = false) async throws -> [String: Any] {
        let body: [String: Any] = [
            "type": type,
            "title": title,
            "message": message,
            "severity": severity,
        ]
        let speakParam = speak ? "?speak=true" : ""
        let data = try await post(path: "/api/v1/alerts/\(speakParam)", body: body)
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw APIError.invalidResponse
        }
        return json
    }

    public func armHoneypot(hash: String) async throws -> [String: Any] {
        let data = try await post(path: "/api/v1/alerts/", body: [
            "type": "security",
            "title": "Honeypot Armed",
            "message": "Honeypot armed with hash: \(hash.prefix(16))...",
            "severity": "high",
            "source": "ios_sovereignty_guard",
        ])
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw APIError.invalidResponse
        }
        return json
    }

    // MARK: - HTTP

    private func get(path: String) async throws -> Data {
        guard let url = URL(string: "\(_baseURL)\(path)") else { throw APIError.invalidURL }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        addAuth(to: &request)
        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        return data
    }

    private func post(path: String, body: [String: Any]) async throws -> Data {
        guard let url = URL(string: "\(_baseURL)\(path)") else { throw APIError.invalidURL }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("devassist420-device-v1", forHTTPHeaderField: "X-Sovereignty-Protocol")
        addAuth(to: &request)
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        return data
    }

    private func addAuth(to request: inout URLRequest) {
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
    }

    private func validateResponse(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else { throw APIError.invalidResponse }
        switch http.statusCode {
        case 200...299: return
        case 400: throw APIError.invalidRequest
        case 401: throw APIError.authenticationFailed
        case 403: throw APIError.forbidden
        default: throw APIError.serverError(http.statusCode)
        }
    }

    public enum APIError: Error, CustomStringConvertible {
        case invalidURL
        case invalidRequest
        case invalidResponse
        case authenticationFailed
        case forbidden
        case serverError(Int)

        public var description: String {
            switch self {
            case .invalidURL: return "Invalid URL"
            case .invalidRequest: return "Invalid request"
            case .invalidResponse: return "Invalid response from server"
            case .authenticationFailed: return "Authentication failed"
            case .forbidden: return "Access forbidden"
            case .serverError(let code): return "Server error: \(code)"
            }
        }
    }
}
