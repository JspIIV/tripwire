// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// An EIP-1967 proxy with an admin who can swap the code, emitting Upgraded each time.
contract PinnedProxy {
    bytes32 private constant SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    address private immutable admin;

    event Upgraded(address indexed implementation);

    constructor(address implementation, bytes memory init) {
        admin = msg.sender;
        assembly { sstore(SLOT, implementation) }
        emit Upgraded(implementation);
        (bool ok, ) = implementation.delegatecall(init);
        require(ok, "init");
    }

    fallback() external payable {
        if (msg.sig == bytes4(keccak256("upgradeTo(address)")) && msg.sender == admin) {
            address next = abi.decode(msg.data[4:], (address));
            assembly { sstore(SLOT, next) }
            emit Upgraded(next);
            return;
        }
        assembly {
            let target := sload(SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
