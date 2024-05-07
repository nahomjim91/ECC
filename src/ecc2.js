import React, { useState } from "react";
import SHA256 from "crypto-js/sha256";

// Elliptic curve parameters
const a = 5; // coefficient 'a' in the curve equation y^2 = x^3 + ax + b
const b = 7; // coefficient 'b' in the curve equation y^2 = x^3 + ax + b
const p = 23; // prime number defining the finite field
const G = [5, 1]; // base point on the curve

// Helper function to compute modular inverse
const modInverse = (a, m) => {
  a = ((a % m) + m) % m;
  for (let x = 1; x < m; x++) {
    if ((a * x) % m === 1) return x;
  }
  return 1;
};

// Elliptic curve point addition
const pointAddition = (P, Q) => {
  if (P[0] === Infinity) return Q;
  if (Q[0] === Infinity) return P;
  if (P[0] === Q[0] && P[1] !== Q[1]) return [Infinity, Infinity];

  const lamda =
    P[0] === Q[0]
      ? ((3 * P[0] * P[0] + a) * modInverse(2 * P[1], p)) % p
      : ((Q[1] - P[1]) * modInverse((Q[0] - P[0] + p) % p, p)) % p;

  const x = (lamda * lamda - P[0] - Q[0]) % p;
  let y = (lamda * (P[0] - x) - P[1]) % p;

  if (y < 0) y = (y + p) % p;

  return [x, y];
};

// Scalar multiplication (point multiplication)
const scalarMultiply = (P, k) => {
  let result = [Infinity, Infinity]; // Point at infinity (identity element)
  let point = P.slice(); // Clone the base point

  while (k > 0) {
    if (k % 2 === 1) {
      result = pointAddition(result, point); // Add current point to result if corresponding bit in k is 1
    }
    point = pointAddition(point, point); // Double the current point
    k = Math.floor(k / 2); // Shift bits to the right
  }
  return result;
};

const AliceBobExample = () => {
  const [alicePrivateKey, setAlicePrivateKey] = useState("");
  const [alicePublicKey, setAlicePublicKey] = useState("");
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState("");
  const [verificationResult, setVerificationResult] = useState("");

  // Generate Alice's key pair
  const generateAliceKeys = () => {
    const randomPrivateKey = Math.floor(Math.random() * 10) + 1;
    console.log("Generating" + randomPrivateKey);
    setAlicePrivateKey(randomPrivateKey.toString());
    const publicKey = scalarMultiply(G, randomPrivateKey);
    setAlicePublicKey(publicKey);
  };

  // Sign message using Alice's private key
  const signMessage = () => {
    // Convert private key to integer
    const privateKeyInt = parseInt(alicePrivateKey, 10);

    // Check if the private key is valid
    if (isNaN(privateKeyInt) || privateKeyInt <= 0 || privateKeyInt >= p) {
      alert("Invalid private key");
      return;
    }

    // Generate a random value k
    const k = Math.floor(Math.random() * 10) + 1;
    console.log("k", k);

    // Calculate the point kG on the elliptic curve
    const kG = scalarMultiply(G, k);

    // Calculate r = x coordinate of kG mod p
    const r = kG[0] % p;

    // Calculate the modular inverse of k
    const kInv = modInverse(k, p);

    // Hash the message
    const hashedMessage = parseInt(SHA256(message).toString(), 16) % p;

    // Calculate s = (hashedMessage + privateKeyInt * r) / k mod p
    const s = (kInv * (hashedMessage + privateKeyInt * r)) % p;

    // Set the signature
    setSignature(`(${r}, ${s})`);
  };

  // Verify message signature using Alice's public key
  const verifySignature = () => {
    const [r, s] = signature
      .replace(/[()]/g, "")
      .split(",")
      .map((value) => parseInt(value.trim(), 10));
    const hashedMessage = parseInt(SHA256(message).toString(), 16) % p;

    if (r < 1 || r >= p || s < 1 || s >= p) {
      setVerificationResult("Invalid signature");
      return;
    }

    const w = modInverse(s, p);
    const u1 = (hashedMessage * w) % p;
    const u2 = (r * w) % p;

    const u1G = scalarMultiply(G, u1);
    const u2PublicKey = scalarMultiply(alicePublicKey, u2);

    const [x1, y1] = pointAddition(u1G, u2PublicKey);

    // Verify if the x-coordinate of the computed point matches the signature's r value
    if (x1 % p === r) {
      setVerificationResult("Signature verified");
    } else {
      setVerificationResult("Signature verification failed");
    }
  };

  return (
    <div>
      <h2 className=" m-2 text-2xl font-bold">Alice Bob Example: ECDSA</h2>
      <button
        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
        onClick={generateAliceKeys}
      >
        Generate Alice's Keys
      </button>
      <div>
        <strong className="mt-4">Alice's Private Key:</strong> {alicePrivateKey}
      </div>
      <div>
        <strong className="mt-4">Alice's Public Key:</strong>{" "}
        {JSON.stringify(alicePublicKey)}
      </div>
      <div>
        <input
          className="mt-4 w-full px-3 py-2 border rounded"
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter Message"
        />
      </div>
      <button
        className="mt-4 bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
        onClick={signMessage}
      >
        Sign Message
      </button>
      <div>
        <strong>Signature:</strong> {signature}
      </div>
      <button
        className="mt-4 bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
        onClick={verifySignature}
      >
        Verify Signature
      </button>
      <div>
        <strong>Verification Result:</strong> {verificationResult}
      </div>
    </div>
  );
};

export default AliceBobExample;
