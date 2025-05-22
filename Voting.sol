// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract EVSVoting {
    address public admin;
    uint256 public votingEnds;

    struct Candidate {
        string name;
        uint256 voteCount;
    }

    Candidate[] public candidates;

    mapping(bytes32 => bool) public nullifiers;

    event VoteCast(bytes32 nullifier, bytes32 commitment, uint indexed candidateIndex);

    modifier onlyBeforeDeadline() {
        require(block.timestamp <= votingEnds, "Voting period is over");
        _;
    }

    modifier onlyAfterDeadline() {
        require(block.timestamp > votingEnds, "Voting is still open");
        _;
    }

    constructor(string[] memory candidateNames, uint256 durationSeconds) {
        admin = msg.sender;
        votingEnds = block.timestamp + durationSeconds;

        for (uint i = 0; i < candidateNames.length; i++) {
            candidates.push(Candidate(candidateNames[i], 0));
        }
    }

    function castVote(
    bytes32 nullifier,
    bytes32 commitment,
    uint candidateIndex
) external onlyBeforeDeadline {
    require(candidateIndex < candidates.length, "Invalid candidate index");
    require(!nullifiers[nullifier], "Duplicate vote detected");

    nullifiers[nullifier] = true;
    candidates[candidateIndex].voteCount += 1;

    emit VoteCast(nullifier, commitment, candidateIndex);
}


    function getCandidate(uint index) external view returns (string memory, uint256) {
        require(index < candidates.length, "Invalid index");
        Candidate memory c = candidates[index];
        return (c.name, c.voteCount);
    }

    function getTotalCandidates() external view returns (uint) {
        return candidates.length;
    }

    function getWinner() external view onlyAfterDeadline returns (string memory name, uint voteCount) {
        uint highest = 0;
        uint winningIndex = 0;
        for (uint i = 0; i < candidates.length; i++) {
            if (candidates[i].voteCount > highest) {
                highest = candidates[i].voteCount;
                winningIndex = i;
            }
        }
        Candidate memory winner = candidates[winningIndex];
        return (winner.name, winner.voteCount);
    }
    }
