import React, { useState, useEffect } from "react";
import SHA256 from "crypto-js/sha256";

// Define parameters for the elliptic curve
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

function DigitalSignature() {
  const [privateKey, setPrivateKey] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState("");
  useEffect(() => {
    // Generate a random private key
    const randomPrivateKey = Math.floor(Math.random() * 10) + 1;
    setPrivateKey(randomPrivateKey.toString());
  }, []);

  // Generate key (private key and public key)
  const generateKeys = () => {
    const privateKeyInt = parseInt(privateKey, 10); // Convert the private key to an integer
    if (isNaN(privateKeyInt)) {
      alert("Please enter a valid private key");
      return;
    }
    const publicKey = scalarMultiply(G, privateKeyInt); // Compute public key by multiplying base point with private key
    setPublicKey(publicKey);
    console.log("Public key", publicKey);
  };

  // Elliptic curve point addition
  const pointAddition = (P, Q) => {
    if (P[0] === Infinity) return Q;
    if (Q[0] === Infinity) return P;
    if (P[0] === Q[0] && P[1] !== Q[1]) return [Infinity, Infinity];
    const lamda = (P[0] === Q[0] && P[1] === Q[1]) ? ((3 * P[0] * P[0] + a) * modInverse(2 * P[1], p)) % p : ((Q[1] - P[1]) * modInverse(Q[0] - P[0], p)) % p;
    const x = (lamda * lamda - P[0] - Q[0]) % p;
    const y = (lamda * (P[0] - x) - P[1]) % p;
    return [x, y];
  };
  

  // Elliptic curve point doubling
  const pointDoubling = (P) => {
    if (P[1] === Infinity) return [Infinity, Infinity];
    const lamda = ((3 * P[0] * P[0] + a) * modInverse(2 * P[1], p)) % p; // Slope of the tangent line
    const x = (lamda * lamda - 2 * P[0]) % p; // x-coordinate of the third point
    const y = (lamda * (P[0] - x) - P[1]) % p; // y-coordinate of the third point
    return [x, y];
  };
  // Scalar multiplication (point multiplication)
  const scalarMultiply = (P, k) => {
    let result = [Infinity, Infinity]; // Point at infinity (identity element)
    let point = P.slice(); // Clone the base point
    while (k > 0) {
      if (k % 2 === 1) {
        console.log('Adding point:', point);
        result = pointAddition(result, point); // Add current point to result if corresponding bit in k is 1
      }
      point = pointDoubling(point); // Double the current point
      console.log('Doubled point:', point);
      k = Math.floor(k / 2); // Shift bits to the right
    }
    return result;
  };
  

//   // Sign message using ECDSA
//   const signMessage = () => {
//     const hashedMessage = parseInt(SHA256(message).toString(), 16) % p; // Hash the message and convert it to an integer modulo p
//     const k = Math.floor(Math.random() * 10) + 1; // Randomly generate ephemeral private key k
//     const kG = scalarMultiply(G, k); // Compute k*G
//     const r = kG[0] % p; // x-coordinate of k*G modulo p
//     const kInv = modInverse(k, p); // Modular inverse of k
//     const s = (kInv * (hashedMessage + privateKey * r)) % p; // Signature component s
//     setSignature(`(${r}, ${s})`); // Set the signature
//   };
  const signMessage = () => {
    const hashedMessage = parseInt(SHA256(message).toString(), 16) % p;
    const k = Math.floor(Math.random() * 10) + 1;
    const kG = scalarMultiply(G, k);
    const r = kG[0] % p;
    const kInv = modInverse(k, p);
    const s = (kInv * (hashedMessage + privateKey * r)) % p;
    setSignature(`(${r}, ${s})`);
  };

  // Verify message signature using ECDSA
  const verifySignature = () => {
    const [r, s] = signature.replace(/[()]/g, '').split(',').map(value => parseInt(value.trim()));
    const hashedMessage = parseInt(SHA256(message).toString(), 16) % p;
  
    if (r < 1 || r >= p || s < 1 || s >= p) {
      alert('Invalid signature');
      return;
    }
  
    const w = modInverse(s, p);
    const u1 = (hashedMessage * w) % p;
    const u2 = (r * w) % p;
    const u1G = scalarMultiply(G, u1);
    const u2PublicKey = scalarMultiply(publicKey, u2);
    console.log('u1G:', u1G);
    console.log('u2PublicKey:', u2PublicKey);
    const [x1, y1] = pointAddition(u1G, u2PublicKey);
    console.log('Computed Point:', [x1, y1]);
  
    if ((x1 % p) === r) {
      alert('Signature verified');
    } else {
      alert('Signature verification failed');
    }
  };
  
  

  return (
    <div className="container mx-auto py-8">
      <button
        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
        onClick={generateKeys}
      >
        Generate Keys
      </button>
      <div className="mt-4">Private Key: {privateKey}</div>
      <div className="mt-4">Public Key: {JSON.stringify(publicKey)}</div>{" "}
      <input
        className="mt-4 w-full px-3 py-2 border rounded"
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Enter Message"
      />
      <button
        className="mt-4 bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
        onClick={signMessage}
      >
        Sign Message
      </button>
      <div className="mt-4">Signature: {signature}</div>
      <button
        className="mt-4 bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
        onClick={verifySignature}
      >
        Verify Signature
      </button>
    </div>
  );
}

export default DigitalSignature;
