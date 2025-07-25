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

    address public owner;

    address public implementation;

    uint256 constant blockRewards = 2 ether;
    // Decreasing 6% for each halving interval
    uint256 constant halvingRate = 94;
    // 2 year length of block with 14 sec block time
    uint256 constant halvingInterval = 4500000;

    modifier onlyOwner() {
        require(msg.sender == owner, 'Not owner');
        _;
    }

    receive() external payable {}

    function init() external {
        require(address(0) == owner || msg.sender == owner, 'Initialized');
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