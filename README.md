# OP_NET Audit Kit

A comprehensive security audit toolkit for OP_NET smart contracts and dApps. Contains documentation, checklists, guidelines, and example contracts for performing thorough audits of OP_NET AssemblyScript smart contracts on Bitcoin L1.

## Contents

### Audit Cheatsheet

`AUDIT-CHEATSHEET.md` — Quick-reference checklist covering critical, high, and medium checks for OP_NET contracts:

- **Critical**: `super.onDeployment()`, `Address.fromString()` params, SHA256 selectors, `increaseAllowance()` vs `approve()`
- **High**: CEI pattern, SafeMath, bounded loops, ReentrancyGuard, access control
- **Medium**: Calldata validation, `Blockchain.call()` return checks, pointer uniqueness, event emission
- **OP_NET-Specific**: No CREATE/CREATE2, CSV timelocks, constructor behavior, `Blockchain.nextPointer`

### Guidelines

Audit and development guidelines for different aspects of OP_NET:

| File | Description |
|------|-------------|
| `guidelines/audit-guidelines.md` | Full security audit methodology and checklist |
| `guidelines/contracts-guidelines.md` | Smart contract development best practices |
| `guidelines/frontend-guidelines.md` | Frontend/dApp integration guidelines |
| `guidelines/backend-guidelines.md` | Backend/API development guidelines |
| `guidelines/plugin-guidelines.md` | OP_NET node plugin development guidelines |
| `guidelines/unit-testing-guidelines.md` | Smart contract testing patterns |
| `guidelines/setup-guidelines.md` | Project setup and dependency versions |
| `guidelines/generic-questions-guidelines.md` | Common Bitcoin L1 via OP_NET questions and answers |

### Documentation

The `docs/` directory contains a mirror of the core OP_NET documentation covering:

- Smart contract runtime (`btc-runtime`) API references
- Core SDK (`@opnet`) provider, contract, and UTXO APIs
- OIP standards (OIP-0001 through OIP-0721)
- Storage system, events, pointers, and serialization
- Quantum resistance and ML-DSA support
- Transaction building and broadcasting

### Example Contracts

The `examples/` directory contains reference contracts for auditing:

- `examples/good/` — Well-written contracts that follow all OP_NET best practices
- `examples/test-patterns/` — Contracts with known issues for testing audit tools

## Usage

This kit is designed to be used as a reference during manual or AI-assisted security audits of OP_NET smart contracts. Start with the `AUDIT-CHEATSHEET.md` for a quick overview, then refer to the full `guidelines/audit-guidelines.md` for detailed methodology.

## License

MIT
