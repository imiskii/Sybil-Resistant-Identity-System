// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {Poseidon} from "poseidon-sol/contracts/Poseidon.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {ConnectionManager} from "../src/ConnectionManager.sol";


contract Deploy is Script {
    function run() external {
        // Anvil account #9 - used as the ROFL mock signer in tests. 
        uint256 deployerKey = 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6;
        // 0x06F7FCD662714B099A6B1C14958FD6D826745616
        address roflMockAddress = vm.envAddress("ROFL_MOCK_ADDRESS");

        vm.startBroadcast(deployerKey);

        // Poseidon is a contract - deploy it first.
        Poseidon poseidonContract = new Poseidon();
        IdentityRegistry registry = new IdentityRegistry(roflMockAddress);
        ConnectionManager manager = new ConnectionManager(
            roflMockAddress,
            address(registry),
            address(poseidonContract)
        );

        vm.stopBroadcast();

        console.log("Poseidon:          ", address(poseidonContract));
        console.log("IdentityRegistry:  ", address(registry));
        console.log("ConnectionManager: ", address(manager));
    }
}
