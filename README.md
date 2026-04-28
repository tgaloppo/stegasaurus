# Stegasaurus

Stegasaurus is a steganography tool for embedding an encrypted message payload into an image. It uses Syndrome-Trellis Codes and a local variance cost function to hide the message in areas with complex texture. Additionally, a randomized Huffman encoding is applied to allow signature free embedding: Stegasaurus uses no fixed markers or header elements. Stegasaurus is written entirely in Julia.

## Technical Specifications

Stegasaurus is composed of the following algorithmic components:

### Syndrome-Trellis Codes (STC)

Stegasaurus uses Syndrome-Trellis Codes to find a minimum cost embedding of the message payload. While not currently adaptive, generator polynomials are configurable at the source level.

### Cost Function

The cost function used is the inverse local variance of the 5x5 pixel block centered on each pixel. The goal is to favor pixels in areas of high variation.

### Permutation

Prior to embedding, the pixels are reordered via a Fisher-Yates shuffle using a cryptographically secure PRNG (AES-256-CTR). This spatially distributes the pixels providing increased opportunity for the STC process while simultaneously adding a layer of randomization to the encoding.

### Payload Encryption

AES-256-CBC encryption is applied to the payload prior to encoding.

### Huffman Encoding / signature Free Embedding

A randomized Huffman encoding is generated with 257 symbols. The 257th symbol is used as an end-of-message marker to recognize message complete during decoding. This allows the message to be embedded with no fixed place markers for length, starting position, or ending position. The randomization is achieved using a cryptographically secure PRNG (AES-256-CTR), and effectively creates a Caesar-cipher over the 257 symbol alphabet. Importantly, Huffman encoding is not being used for compression purposes; its sole purpose is to allow a signature free embedding.

## Known Weakness

The current implementation derives a salt value from the password itself; this means that the same Huffman encoding and permutation will be repeated if the same password is used multiple times. It is strongly suggested to use a unique password for each embedding. 

## Installation

Stegasaurus was written using Julia 1.12.6. Clone the repository and instantiate the environment to download the required cryptographic and image processing dependencies.

```bash
git clone https://gitlab.com/tgaloppo/stegasaurus.git
cd stegasaurus
julia --project=. -e 'using Pkg; Pkg.instantiate()'
```

## Usage

### Embedding

To embed the message "Hello World!" into the image "test.jpg" resulting in the image "hello.png":

```bash
julia --project=. src/stegasaurus.jl embed -m "Hello World!" test.jpg hello.png
```

To embed the file "secret_recipe.txt" into the image "test.jpg" resulting in the image "recipe.png":

```bash
julia --project=. src/stegasaurus.jl embed -f secret_recipe.txt test.jpg recipe.png
```

*IMPORTANT*: You *MUST* use an output image format with *LOSSLESS* compression. Using a non-lossless compression will corrupt the embedding.

### Extraction

To extract the embedded payload from file "secret.png" into file "output.txt":

```bash
julia --project=. src/stegasaurus.jl extract secret.png output.txt
```

During *extraction only*, if no output file is specified, the output will be printed to stdout.
If no message is found, or if the password is incorrect, the tool will simply report no message found.
