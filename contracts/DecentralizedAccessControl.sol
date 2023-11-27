// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./proof-of-identity/ProofOfIdentity.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// import "https://github.com/haven1network/proof-of-identity-hackathon/blob/main/contracts/proof-of-identity/ProofOfIdentity.sol";

contract DecentralizedAccessControl is Ownable {
    // Proof of Identity contract instance
    ProofOfIdentity private proofOfIdentity;

    // Mapping of resource ID to access flag (true if resource is available)
    mapping(uint256 => bool) private resourceAccess;

    // Events
    event ResourceAccessUpdated(uint256 indexed resourceId, bool access);
    event AccessGranted(address indexed user, uint256 resourceId);
    event AccessDenied(address indexed user, uint256 resourceId);

    // Constructor to set ProofOfIdentity contract address
    constructor(address poiContractAddress) {
        proofOfIdentity = ProofOfIdentity(poiContractAddress);
    }

    // Modifier to check user identity
    modifier onlyVerifiedUser(uint256 resourceId) {
        // Fetch user identity attributes from ProofOfIdentity contract
        (bool isVerified, , ) = proofOfIdentity.getPrimaryID(msg.sender);
        require(isVerified, "User not verified");

        // Implement custom logic to allow access based on user attributes
        // Example: Require users to be from a specific country
        (string memory countryCode, , ) = proofOfIdentity.getCountryCode(
            msg.sender
        );
        require(resourceAccess[resourceId], "Resource not accessible");
        require(
            keccak256(abi.encodePacked(countryCode)) ==
                keccak256(abi.encodePacked("US")),
            "Access restricted to specific country"
        );

        _;
    }

    // Function to update resource access
    function updateResourceAccess(
        uint256 resourceId,
        bool access
    ) public onlyOwner {
        resourceAccess[resourceId] = access;
        emit ResourceAccessUpdated(resourceId, access);
    }

    // Function for users to access a resource
    function accessResource(
        uint256 resourceId
    ) public onlyVerifiedUser(resourceId) {
        // Access logic for the resource
        emit AccessGranted(msg.sender, resourceId);
    }
}
