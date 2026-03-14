# GitHub Security MCP

## Project Context

Bu proje hackbrowser-mcp (browser security testing) ve cloud-audit-mcp (AWS/Azure/GCP misconfig detection) sonrasında üçüncü MCP projesi. GitHub'ın Enterprise Security özelliklerini open-source MCP olarak sunacak — AI agent'a GitHub API'lerini vererek organization, repository, workflow, secret, dependency güvenlik analizi yapacak.

### Neden Bu MCP?

GitHub Advanced Security (GHAS) Enterprise lisans gerektirir. Secret scanning, code scanning, Dependabot gibi özellikler var ama hepsi GitHub UI'da. Hiçbiri AI agent'a MCP üzerinden kontrol vermiyor. Fark: GHAS'ı açarsın dashboard'dan bakarsın. Bu MCP'de agent direkt GitHub API'lerini çağırır, org/repo/workflow security posture'unu analiz eder, attack path'leri bulur, fix önerir.

### Hedef Kullanım

```
User: "GitHub organizasyonumdaki en kritik 5 security issue'yu bul"

Agent: → Org settings'i kontrol eder (2FA, SSO, member privileges)
       → Repo'ları tarar (branch protection, secret scanning, code scanning)
       → Workflow'ları analiz eder (injection, unpinned actions, over-permissive GITHUB_TOKEN)
       → Bulguları severity'ye göre sıralar
       → Her biri için fix komutu/config verir
```

### Taranacak Alanlar

**Organization Security:**
- 2FA enforcement
- SSO/SAML configuration
- Member privileges (repo creation, forking, visibility defaults)
- Outside collaborators audit
- OAuth app / GitHub App installations
- IP allowlists
- Audit log patterns

**Repository Security:**
- Branch protection rules (require reviews, signed commits, admin bypass)
- CODEOWNERS enforcement
- Secret scanning enabled + alerts
- Code scanning (CodeQL) enabled + alerts
- Dependabot enabled + security alerts
- Security policy (SECURITY.md)
- Private vulnerability reporting
- Deploy keys audit
- Webhook security (insecure URLs, exposed secrets)
- Fork settings (allow fork, fork visibility)

**GitHub Actions Security:**
- Workflow injection (untrusted inputs: github.event.*, run:)
- pull_request_target + checkout PR head = arbitrary code execution
- Unpinned actions (tag vs SHA pinning)
- GITHUB_TOKEN default permissions (read-all vs least-privilege)
- Self-hosted runner exposure
- Environment protection rules
- Fork PR workflow approval settings
- Reusable workflow trust
- Artifact upload/download security
- OIDC for cloud deployments

**Secrets & Credentials:**
- Secret scanning coverage
- Push protection enabled
- Custom secret patterns
- Exposed secrets in workflow logs
- Environment vs repo vs org secret scoping

**Supply Chain:**
- Dependency graph enabled
- Dependabot security updates
- SBOM generation
- Known vulnerability count (Dependabot alerts)
- License compliance

**Access Control:**
- Team permissions audit
- Collaborator access levels
- Deploy key permissions (read-only vs read-write)
- GitHub App permission scope
- Fine-grained PAT vs classic token usage

## Technical Stack

- **Runtime:** Bun + TypeScript (hackbrowser-mcp / cloud-audit-mcp ile aynı)
- **Protocol:** MCP (stdio transport)
- **SDK:** @modelcontextprotocol/sdk
- **GitHub API:** @octokit/rest + @octokit/graphql (GitHub REST API v3 + GraphQL v4)
- **Architecture:** hackbrowser-mcp pattern'i takip et — tools.ts (Zod schema), mcp-server.ts (stdio), ayrı category dosyaları

## Related Projects

- **hackbrowser-mcp:** https://github.com/badchars/hackbrowser-mcp — Browser-based security testing MCP
- **cloud-audit-mcp:** https://github.com/badchars/cloud-audit-mcp — Cloud security audit MCP (AWS/Azure/GCP)
- **recon0:** https://github.com/badchars/recon0 — Bug bounty recon pipeline

## Developer

- **Author:** Orhan Yildirim
- **GitHub:** https://github.com/badchars
- **Book:** [Agentic AI for Offensive Cybersecurity](https://www.amazon.com/dp/B0GFD44D84)
- **License:** MIT

## Rules

- Runtime: Bun (Node.js değil)
- Dil: TypeScript strict mode
- Dependency az tut — sadece Octokit + MCP SDK + Zod
- Her security category ayrı modülde (org/, repo/, actions/, secrets/, supply-chain/, access/)
- Tool isimleri: `github_check_org_2fa`, `github_check_repo_branch_protection`, `github_check_workflow_injection` gibi category prefix'li
- Zod schema her tool için zorunlu
- Türkçe yorum yazma, İngilizce kod + yorum
- gh CLI kullanma — sadece Octokit SDK (REST + GraphQL)
- README: hackbrowser-mcp kalitesinde, banner + badges + karşılaştırma tablosu
