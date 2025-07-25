// SPDX-License-Identifier: GPL-3.0
// Copyright 2025 The core-geth Authors
// This file is part of the core-geth library.
//
// The core-geth library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The core-geth library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the core-geth library. If not, see <http://www.gnu.org/licenses/>.

pragma solidity ^0.8.28;

contract ConsensusView {
    event UpdatedOwner(address newOwner);
    event UpdatedImplementation(address newImplementation);
    event Sent(address to, uint256 value, bool success);

    address public owner;

    address public implementation;

    uint256 constant blockRewards = 1 ether;
    // Decreasing 2% for each halving interval
    uint256 constant halvingRate = 98;
    // 1 year length of block with 14 sec block time
    uint256 constant halvingInterval = 2200000;

    modifier onlyOwner() {
        require(msg.sender == owner, 'Not owner');
        _;
    }

    receive() external payable {}

    function init() external {
        require(address(0) == owner, 'Initialized');
        owner = msg.sender;
        (bool success,) = owner.call{ value: address(this).balance }('');
        require(success, 'Call failed');
        emit UpdatedOwner(msg.sender);
    }

    function updateOwner(address newOwner) external onlyOwner {
        owner = newOwner;
        emit UpdatedOwner(newOwner);
    }

    function updateImplementation(address newImplementation) external onlyOwner {
        implementation = newImplementation;
        emit UpdatedImplementation(newImplementation);
    }

    function send(address[] memory addresses, uint256[] memory amounts, uint256 gasLimit) external payable {
        for (uint i; i < addresses.length; ++i) {
            (bool success, ) = addresses[i].call{ value: amounts[i], gas: gasLimit }('');

            emit Sent(addresses[i], amounts[i], success);
        }
        if (address(this).balance != 0) {
            uint256 balance = address(this).balance;
            (bool success, ) = msg.sender.call{ value: balance }('');
            emit Sent(msg.sender, balance, success);
        }
    }

    function getBlockRewardsRef(uint256 nHeight, address coinbase) public pure returns (bool staked, address[] memory addresses, uint256[] memory rewards) {
        addresses = new address[](1);
        rewards = new uint256[](1);
        
        uint256 halvings = nHeight / halvingInterval;

        uint256 reward = blockRewards;

        for (uint i; i < halvings; ++i) {
            reward = reward * halvingRate / 100;
        }

        staked = true;
        addresses[0] = coinbase;
        rewards[0] = reward;
    }

    function getBlockRewards(uint256 nHeight, address coinbase) external view returns (bool staked, address[] memory addresses, uint256[] memory rewards) {
        if (implementation == address(0)) {
            return getBlockRewardsRef(nHeight, coinbase);
        }
        (bool success, bytes memory data) = implementation.staticcall(
            abi.encodeWithSelector(ConsensusView.getBlockRewards.selector, nHeight, coinbase)
        );
        if (!success || data.length == 0) {
            assembly {
                revert(add(32, data), mload(data))
            }
        }
        return abi.decode(data, (bool, address[], uint256[]));
    }
}