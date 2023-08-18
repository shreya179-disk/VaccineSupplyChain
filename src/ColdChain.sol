// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library CryptoSuite {
    function spiltsignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65);

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96))) // Corrected index
        }

        return (v, r, s);
    }

    function recoverSigner(bytes32 message, bytes memory sig) internal pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = spiltsignature(sig);

        return ecrecover(message, v, r, s);
    }
}

contract ColdChain {
    enum Status { MANUFACTURED, DELIVERING_INTERNATIONAL, STORED, DELIVERING_LOCAL, DELIVERED }

    struct Certificate {
        uint id;
        Entity issuer;
        Entity prover;
        bytes signature;
        Status status;
    }

    enum Mode { ISSUER, PROVER, VERIFIER }

    struct Entity {
        address id;
        Mode mode;
        uint[] certificateIds;
    }

    struct VaccineBatch {
        uint id;
        address manufacturer;
        string brand;
        uint[] certificateIds;
    }

    uint public constant MAX_CERTIFICATIONS = 2;
    uint[] public vaccineBatchIds;
    Certificate[] public certificates; // Added array to store certificates

    mapping(uint => VaccineBatch) public vaccineBatches;
    mapping(address => Entity) public entities;

    event AddEntity(address entityId, string entityMode);
    event AddVaccineBatch(uint vaccineBatchId, address indexed manufacturer);
    event IssueCertificate(address indexed issuer, address indexed prover, uint certificateId);

    function addEntity(address _id, string memory _mode) public returns (uint) {
        Mode mode = unmarshalMode(_mode);
        uint[] memory _certificateIds = new uint[](MAX_CERTIFICATIONS);
        Entity memory entity = Entity(_id, mode, _certificateIds);
        entities[_id] = entity;

        emit AddEntity(_id, _mode);
        return entities[_id].certificateIds.length;
    }

    function addVaccineBatch(string memory brand, address manufacturer) public returns (uint) {
        uint[] memory _certificateIds = new uint[](MAX_CERTIFICATIONS);
        uint id = vaccineBatchIds.length;
        VaccineBatch memory batch = VaccineBatch(id, manufacturer, brand, _certificateIds);
        vaccineBatches[id] = batch;
        vaccineBatchIds.push(id);

        emit AddVaccineBatch(id, manufacturer);
        return id;
    }
    function IssueCertification(address _issuer, address _prover, Status _status,
    uint vaccineBatchId, bytes memory signature) public returns (uint) {
    Entity memory issuer = entities[_issuer];
    require(issuer.mode == Mode.ISSUER, "Only ISSUER can issue certificates");

    Entity memory prover = entities[_prover];
    require(prover.mode == Mode.PROVER, "Only PROVER can be assigned a certificate");

    uint id = certificates.length;
    Certificate memory certificate = Certificate(id, issuer, prover, signature, _status);
    certificates.push(certificate); // Store the certificate

    emit IssueCertificate(_issuer, _prover, id);
    return id;
}

   function unmarshalMode(string memory _mode) private pure returns (Mode) {
        bytes32 encodedMode = keccak256(abi.encodePacked(_mode)); 
        bytes32 encodedMode0 = keccak256(abi.encodePacked("ISSUER"));
        bytes32 encodedMode1 = keccak256(abi.encodePacked("PROVER"));
        bytes32 encodedMode2 = keccak256(abi.encodePacked("VERIFIER"));

        if (encodedMode == encodedMode0) {
            return Mode.ISSUER;
        } else if (encodedMode == encodedMode1) {
            return Mode.PROVER;
        } else if (encodedMode == encodedMode2) {
            return Mode.VERIFIER;
        }
        revert("Received invalid entities mode"); 
    }
    
    function unmarshalStatus(string memory _status) private pure returns (Status) {
        bytes32 encodedStatus = keccak256(abi.encodePacked(_status)); 
        bytes32 encodedStatus0 = keccak256(abi.encodePacked("MANUFACTURED"));
        bytes32 encodedStatus1 = keccak256(abi.encodePacked("DELIVERING_INTERNATIONAL"));
        bytes32 encodedStatus2 = keccak256(abi.encodePacked("STORED"));
        bytes32 encodedStatus3 = keccak256(abi.encodePacked("DELIVERING_LOCAL"));
        bytes32 encodedStatus4 = keccak256(abi.encodePacked("DELIVERED"));

        if (encodedStatus == encodedStatus0) {
            return Status.MANUFACTURED;
        } else if (encodedStatus == encodedStatus1) {
            return Status.DELIVERING_INTERNATIONAL;
        } else if (encodedStatus == encodedStatus2) {
            return Status.STORED;
        } else if (encodedStatus == encodedStatus3) {
            return Status.DELIVERING_LOCAL;
        } else if (encodedStatus == encodedStatus4) {
            return Status.DELIVERED;
        }

        revert("Received invalid certification status"); 
    }

   function isMatchingSignature(bytes32 message, uint id, address issuer) public view returns (bool) {
    Certificate memory cert = certificates[id];
    require(cert.issuer.id == issuer);

    address recoveredSigner = CryptoSuite.recoverSigner(message, cert.signature);
    return recoveredSigner == cert.issuer.id;
  }

}
