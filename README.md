Power Side-Channel Attack on an AES-128 Embedded Device
1. Introduction

In modern embedded systems, cryptographic algorithms such as AES are widely deployed to ensure confidentiality. While these algorithms are mathematically secure, their physical implementations may introduce unintended information leakage. This challenge illustrates a realistic scenario where an attacker exploits such leakage to recover a secret key.

The objective of this work is to perform a power side-channel attack on a remote AES-128 device. By collecting and analyzing power consumption traces during encryption, we aim to reconstruct the secret encryption key without breaking the algorithm itself.

2. Attack Model and Scenario

The challenge provides access to a remote laboratory environment simulating a captured embedded device. The architecture can be summarized as follows:

A target device performs AES-128 encryption
An oscilloscope measures the instantaneous power consumption during execution
The traces are transmitted to a remote interface
The attacker can interact with the system via a TCP socket

The attacker has the following capabilities:

Send chosen plaintexts to the device
Receive corresponding power consumption traces
Submit a candidate AES key for verification

This setting corresponds to a chosen-plaintext side-channel attack, which is a strong and realistic threat model in embedded security.

3. Physical Basis of the Attack

The attack relies on the fundamental observation that:

The power consumption of a digital circuit depends on the data being processed.

In CMOS circuits, switching activity (i.e., transitions between logic states) results in variations in power consumption. As a consequence, intermediate values computed during cryptographic operations can be indirectly observed through power measurements.

A common and effective assumption is that the leakage correlates with the Hamming Weight (HW) of the processed data, defined as the number of bits set to 1 in a byte.

4. Targeted Leakage in AES

The attack targets the first round of AES, specifically the following transformation:

𝑆
=
SBOX
(
𝑃
⊕
𝐾
)
S=SBOX(P⊕K)

Where:

𝑃
P is a known plaintext byte
𝐾
K is an unknown key byte
𝑆
S is the output of the AES S-box

Since the plaintext is known, we can compute hypothetical intermediate values for any key guess 
𝑘
k:

𝑆
𝑘
=
SBOX
(
𝑃
⊕
𝑘
)
S
k
	​

=SBOX(P⊕k)

We then model the leakage as:

𝐿
𝑘
=
𝐻
𝑊
(
𝑆
𝑘
)
L
k
	​

=HW(S
k
	​

)

This provides a predicted power consumption for each key hypothesis.

5. Methodology: Correlation Power Analysis (CPA)

To recover the key, we apply Correlation Power Analysis (CPA), which consists of the following steps:

5.1 Trace Acquisition

A large number of traces are collected by sending random plaintexts to the device. Each trace represents the power consumption during a single AES execution.

5.2 Hypothesis Generation

For each key byte (16 in total), all 256 possible values are tested. For each hypothesis, we compute the predicted leakage using the Hamming Weight model.

5.3 Statistical Analysis

We compute the Pearson correlation coefficient between:

The predicted leakage values
The actual measured traces

The correct key hypothesis is expected to yield the highest correlation with the measured data.

6. Implementation Details

The provided socket_interface.py file is used to:

Communicate with the remote device
Send plaintexts (Option 1)
Receive base64-encoded power traces
Submit a key candidate (Option 2)

A custom script extends this interface to:

Collect multiple traces
Decode them into NumPy arrays
Perform CPA using vectorized operations
Recover each key byte independently

Key implementation aspects include:

Trace normalization to improve numerical stability
Filtering inconsistent traces
Efficient correlation computation using NumPy
7. Key Recovery

The CPA is applied independently to each of the 16 key bytes. For each byte:

The hypothesis with the maximum correlation is selected
The process is repeated until the full 128-bit key is reconstructed

Once the key is obtained, it is encoded in hexadecimal format and submitted to the remote service. A correct key results in the retrieval of the challenge flag.

8. Results and Discussion

The attack successfully recovers the AES-128 key using only:

Chosen plaintexts
Passive power measurements

This demonstrates that even strong cryptographic algorithms can be compromised if their physical implementations are not properly secured.

The effectiveness of the attack depends on:

The number of traces collected
The signal-to-noise ratio
The accuracy of the leakage model
9. Conclusion

This challenge highlights the importance of considering implementation-level security in cryptographic systems. While AES remains secure from a theoretical standpoint, side-channel attacks such as CPA can completely bypass its security by exploiting physical leakage.

In real-world systems, countermeasures such as:

Masking
Hiding (noise injection)
Constant-time implementations

are essential to mitigate such attacks.

10. Key Takeaways
Cryptographic security must include physical security considerations
Side-channel attacks exploit information leakage, not algorithmic weaknesses
CPA is a powerful technique requiring only statistical analysis
Embedded systems are particularly vulnerable to such attacks
