# Secureum-Checklist

## General Code security pitfails
### Incorrect access control: 
Contract functions executing critical logic should have appropriate access control enforced via address checks (e.g. owner, controller etc.) typically in modifiers. Missing checks allow attackers to control critical logic. 

- Unprotected withdraw function: Unprotected (external/public) function calls sending Ether/tokens to user-controlled addresses may allow users to withdraw unauthorized funds. (see here)

- Unprotected call to selfdestruct: A user/attacker can mistakenly/intentionally kill the contract. Protect access to such functions. (see here)

### Incorrect modifier

- Modifiers should only implement checks and not make state changes and external calls which violates the checks-effects-interactions pattern. These side-effects may go unnoticed by developers/auditors because the modifier code is typically far from the function implementation

- If a modifier does not execute _ or revert, the function using that modifier will return the default value causing unexpected behavior.

### Controlled delegatecall

delegatecall() or callcode() to an address controlled by the user allows execution of malicious contracts in the context of the caller’s state. Ensure trusted destination addresses for such calls.

### Reentrancy vulnerabilities

- Reentrancy: Untrusted external contract calls could callback leading to unexpected results such as multiple withdrawals or out-of-order events. Use check-effects-interactions pattern or reentrancy guards.

- ERC777 callbacks and reentrancy: ERC777 tokens allow arbitrary callbacks via hooks that are called during token transfers. Malicious contract addresses may cause reentrancy on such callbacks if reentrancy guards are not used.


### Private on-chain data: 

Marking variables private does not mean that they cannot be read on-chain. Private data should not be stored unencrypted in contract code or state but instead stored encrypted or off-chain.

### Weak PRNG: 
PRNG relying on block.timestamp, now or blockhash can be influenced by miners to some extent and should be avoided. 

### Block values as time proxies:

block.timestamp and block.number are not good proxies (i.e. representations, not to be confused with smart contract proxy/implementation pattern) for time because of issues with synchronization, miner manipulation and changing block times. 

### Integer overflow/underflow
Not using OpenZeppelin’s SafeMath (or similar libraries) that check for overflows/underflows may lead to vulnerabilities or unexpected behavior if user/attacker can control the integer operands of such arithmetic operations. Solc v0.8.0 introduced default overflow/underflow checks for all arithmetic operations. 

### Divide before multiply
Performing multiplication before division is generally better to avoid loss of precision because Solidity integer division might truncate.

### Transaction order dependence
- Transaction order dependence: Race conditions can be forced on specific Ethereum transactions by monitoring the mempool. For example, the classic ERC20 approve() change can be front-run using this method. Do not make assumptions about transaction order dependence. 

- ERC20 approve() race condition: Use safeIncreaseAllowance() and safeDecreaseAllowance() from OpenZeppelin’s SafeERC20 implementation to prevent race conditions from manipulating the allowance amounts.

### Signature malleability: 
The ecrecover function is susceptible to signature malleability which could lead to replay attacks. Consider using OpenZeppelin’s ECDSA library.

### ERC20 transfer() does not return boolean: 
Contracts compiled with solc >= 0.4.22 interacting with such functions will revert. Use OpenZeppelin’s SafeERC20 wrappers. 

### Incorrect return values for ERC721 ownerOf(): 
Contracts compiled with solc >= 0.4.22 interacting with ERC721 ownerOf() that returns a bool instead of address type will revert. Use OpenZeppelin’s ERC721 contracts. 

### Unexpected Ether and this.balance
 A contract can receive Ether via payable functions, selfdestruct(), coinbase transaction or pre-sent before creation. Contract logic depending on this.balance can therefore be manipulated. 
 
 ### Locked Ether
 Contracts that accept Ether via payable functions but without withdrawal mechanisms will lock up that Ether. Remove payable attribute or add withdraw function. 
 
### Contract check: 
Checking if a call was made from an Externally Owned Account (EOA) or a contract account is typically done using extcodesize check which may be circumvented by a contract during construction when it does not have source code available. Checking if tx.origin == msg.sender is another option. Both have implications that need to be considered. 

 ### Account existence check for low-level calls: 
 Low-level calls call/delegatecall/staticcall return true even if the account called is non-existent (per EVM design). Account existence must be checked prior to calling if needed.
 
 ### Return values of low-level calls: 
 Ensure that return values of low-level calls (call/callcode/delegatecall/send/etc.) are checked to avoid unexpected failures.
 
 ### Calls inside a loop: 
 Calls to external contracts inside a loop are dangerous (especially if the loop index can be user-controlled) because it could lead to DoS if one of the calls reverts or execution runs out of gas. Avoid calls within loops, check that loop index cannot be user-controlled or is bounded. 
 
 ### DoS with block gas limit: 
 Programming patterns such as looping over arrays of unknown size may lead to DoS when the gas cost of execution exceeds the block gas limit. 
 
 ### Missing events for critical operations: 
 Events for critical state changes (e.g. owner and other critical parameters) should be emitted for tracking this off-chain.
 
 ### Missing zero address validation: 
 Setters of address type parameters should include a zero-address check otherwise contract functionality may become inaccessible or tokens burnt forever.
 
### Missing Two-Step procces for critical address change: 
Changing critical addresses in contracts should be a two-step process where the first transaction (from the old/current address) registers the new address (i.e. grants ownership) and the second transaction (from the new address) replaces the old address with the new one (i.e. claims ownership). This gives an opportunity to recover from incorrect addresses mistakenly used in the first step. If not, contract functionality might become inaccessible

### ERC20 transfer and transferFrom: 
Should return a boolean. Several tokens do not return a boolean on these functions. As a result, their calls in the contract might fail.

### Guarded launch
- via asset limits: Limiting the total asset value managed by a system initially upon launch and gradually increasing it over time may reduce impact due to initial vulnerabilities or exploits. 

- via asset types: Limiting types of assets that can be used in the protocol initially upon launch and gradually expanding to other assets over time may reduce impact due to initial vulnerabilities or exploits.

- via user limits: Limiting the total number of users that can interact with a system initially upon launch and gradually increasing it over time may reduce impact due to initial vulnerabilities or exploits. Initial users may also be whitelisted to limit to trusted actors before opening the system to everyone.

- via usage limits: Enforcing transaction size limits, daily volume limits, per-account limits, or rate-limiting transactions may reduce impact due to initial vulnerabilities or exploits. 

- via composability limits: Restricting the composability of the system to interface only with whitelisted trusted contracts before expanding to arbitrary external contracts may reduce impact due to initial vulnerabilities or exploits. 

- via escrows: Escrowing high value transactions/operations with time locks and a governance capability to nullify or revert transactions may reduce impact due to initial vulnerabilities or exploits. 

- via circuit breakers: Implementing capabilities to pause/unpause a system in extreme scenarios may reduce impact due to initial vulnerabilities or exploits. 

- via emergency shutdown: Implement capabilities that allow governance to shutdown new activity in the system and allow users to reclaim assets may reduce impact due to initial vulnerabilities or exploits. 

## Function Related
### Function parameters: 
Ensure input validation for all function parameters especially if the visibility is external/public where (untrusted) users can control values. This is especially required for address parameters where maliciously/accidentally used incorrect/zero addresses can cause vulnerabilities or unexpected behavior.

### Solidity Function 
- arguments: Ensure that the arguments to function calls at the caller sites are the correct ones and in the right order as expected by the function definition.

- visibility: Ensure that the strictest visibility is used for the required functionality. An accidental external/public visibility will allow (untrusted) users to invoke functionality that is supposed to be restricted internally

- modifiers: Ensure that the right set of function modifiers are used (in the correct order) for the specific functions so that the expected access control or validation is correctly enforced.

- return values: Ensure that the appropriate return value(s) are returned from functions and checked without ignoring at function call sites, so that error conditions are caught and handled appropriately.

- invocation timeliness: Externally accessible functions (external/public visibility) may be called at any time (or never). It is not safe to assume they will only be called at specific system phases (e.g. after initialization, when unpaused, during liquidation) that is meaningful to the system design. The reason for this can be accidental or malicious. Function implementation should be robust enough to track system state transitions, determine meaningful states for invocations and withstand arbitrary calls. For e.g., initialization functions (used with upgradeable contracts that cannot use constructors) are meant to be called atomically along with contract deployment to prevent anyone else from initializing with arbitrary values.

- invocation repetitiveness: Externally accessible functions (external/public visibility) may be called any number of times. It is not safe to assume they will only be called only once or a specific number of times that is meaningful to the system design. Function implementation should be robust enough to track, prevent, ignore or account for arbitrarily repetitive invocations. For e.g., initialization functions (used with upgradeable contracts that cannot use constructors) are meant to be called only once.

- invocation order:  Externally accessible functions (external/public visibility) may be called in any order (with respect to other defined functions). It is not safe to assume they will only be called in the specific order that makes sense to the system design or is implicitly assumed in the code. For e.g., initialization functions (used with upgradeable contracts that cannot use constructors) are meant to be called before other system functions can be called.

- invocation arguments: Externally accessible functions (external/public visibility) may be called with any possible arguments. Without complete and proper validation (e.g. zero address checks, bound checks, threshold checks etc.), they cannot be assumed to comply with any assumptions made about them in the code.


## Documentation
### System specification: 
Ensure that the specification of the entire system is considered, written and evaluated to the greatest detail possible. Specification describes how (and why) the different components of the system behave to achieve the design requirements. Without specification, a system implementation cannot be evaluated against the requirements for correctness.

### System documentation:
Ensure that roles, functionalities and interactions of the entire system are well documented to the greatest detail possible. Documentation describes what (and how) the implementation of different components of the system does to achieve the specification goals. Without documentation, a system implementation cannot be evaluated against the specification for correctness and one will have to rely on analyzing the implementation itself.

### Access control specification: 
Ensure that the various system actors, their access control privileges and trust assumptions are accurately specified in great detail so that they are correctly implemented and enforced across different contracts, functions and system transitions/flows

## Tests
### Tests: 
Tests indicate that the system implementation has been validated against the specification. Unit tests, functional tests and integration tests should have been performed to achieve good test coverage across the entire codebase. Any code or parameterisation used specifically for testing should be removed from production code.

