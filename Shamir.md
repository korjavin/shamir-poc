# Shamir's Secret Sharing Implementation

## Overview

This document describes our implementation of Shamir's Secret Sharing scheme for the secret management application. The implementation allows users to recover their secrets by providing only a subset of correct answers to their secret questions, rather than requiring all answers to be correct.

## Mathematical Background

Shamir's Secret Sharing is based on the mathematical principle that a polynomial of degree k-1 can be uniquely determined by k points on the curve. For example, 2 points uniquely define a line, 3 points uniquely define a quadratic curve, and so on.

### Key Concepts

1. **Secret**: The value we want to protect and later reconstruct
2. **Shares**: Pieces of information derived from the secret
3. **Threshold**: The minimum number of shares needed to reconstruct the secret
4. **Polynomial**: A mathematical function used to generate shares

## Our Implementation

In our application, we use Shamir's Secret Sharing as follows:

### Share Generation

1. Each answer to a secret question is used to generate a share
2. The position of the answer (1, 2, 3, etc.) is used as the x-coordinate
3. A hash of the answer is used as the y-coordinate
4. Together, these form a point (x, y) on a polynomial

### Secret Reconstruction

1. When a user attempts to decrypt a secret, they provide answers to their questions
2. Each answer generates a share (x, y)
3. If at least the threshold number of answers are correct, the shares can be used to reconstruct the original polynomial
4. The secret is the value of the polynomial at x=0

### Threshold Setting

We use a threshold of approximately 2/3 of the total number of questions:

```javascript
const threshold = Math.max(2, Math.ceil(answers.length * 2/3));
```

This means:
- For 3 questions, you need at least 2 correct answers
- For 5 questions, you need at least 4 correct answers
- For 6 questions, you need at least 4 correct answers

The minimum threshold is 2, as you need at least 2 points to define a line.

## Technical Implementation

### Share Generation

1. Each answer is hashed to create a consistent y-value:
   ```javascript
   const answerHash = sha256(answer);
   const yValue = new BigInt(answerHash);
   ```

2. The position of the answer is used as the x-value:
   ```javascript
   const xValue = BigInt(i + 1);
   ```

3. These values form a share:
   ```javascript
   const share = { x: xValue, y: yValue };
   ```

### Lagrange Interpolation

To reconstruct the secret, we use Lagrange interpolation to find the value of the polynomial at x=0:

```javascript
function lagrangeInterpolation(shares, x, prime) {
    let result = BigInt(0);
    
    for (let i = 0; i < shares.length; i++) {
        let numerator = BigInt(1);
        let denominator = BigInt(1);
        
        for (let j = 0; j < shares.length; j++) {
            if (i !== j) {
                numerator = (numerator * (x - shares[j].x)) % prime;
                denominator = (denominator * (shares[i].x - shares[j].x)) % prime;
            }
        }
        
        const lagrange = (numerator * modInverse(denominator, prime)) % prime;
        result = (result + (shares[i].y * lagrange)) % prime;
    }
    
    return result;
}
```

### Key Derivation

The reconstructed secret is then used to derive an encryption key:

1. The secret is padded or truncated to ensure it's exactly 32 bytes
2. The secret is combined with a salt using PBKDF2
3. The resulting key is used for AES-GCM encryption/decryption

## Security Considerations

1. **Information Theoretic Security**: With fewer than the threshold number of shares, no information about the secret is revealed
2. **Brute Force Resistance**: Even with t-1 shares, an attacker would need to brute force the remaining share
3. **Answer Independence**: Each answer is independent, so knowing some answers doesn't help guess others

## Practical Benefits

1. **Fault Tolerance**: Users can forget some of their answers and still recover their secrets
2. **Usability**: Reduces frustration from having to remember all answers exactly
3. **Security**: Maintains strong security while improving user experience

## Implementation Notes

Our implementation uses:
- BigInt for precise mathematical operations
- A large prime number for finite field arithmetic
- Proper error handling for cases where not enough correct answers are provided
- Fallback mechanisms in case the primary implementation fails

## Conclusion

Shamir's Secret Sharing provides an elegant solution to the problem of secret recovery, allowing users to recover their secrets with only a subset of correct answers while maintaining strong security properties.
