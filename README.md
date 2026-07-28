# Perbandingan Kualitas Visual Penyisipan Digital Signature Standards pada Game Sprite (PNG) Menggunakan Metode LSB Steganography

<div align="center">
  <a href="https://ejournal2.unud.ac.id/index.php/jnatia/en">
    <img width="4000" height="400" alt="pageHeaderLogoImage_en" src="https://github.com/user-attachments/assets/da25d3de-2d7c-4eca-bd8f-364de7eabc82" />
  </a>

  <p align="center">
    Scripts for a comparative study measuring the visual-quality cost (PSNR, SSIM) of embedding RSA, Ed25519, and CRYSTALS-Dilithium digital signatures into PNG game sprites using LSB steganography.
    <br/>
    <!-- <a href="https://ejournal2.unud.ac.id/index.php/jnatia/en"><strong>Read the paper »</strong></a> -->
  </p>
</div>

## About The Project

This repository contains the implementation of a comparative study on digital signature embedding in PNG game sprites. The project evaluates the visual quality impact of three cryptographic signature standards using Least Significant Bit (LSB) steganography:

- **RSA** - Traditional public-key cryptography
- **Ed25519** - Modern elliptic-curve signature scheme
- **CRYSTALS-Dilithium** - Post-quantum cryptographic signature algorithm

Quality metrics are measured using:
- **PSNR** (Peak Signal-to-Noise Ratio)
- **SSIM** (Structural Similarity Index)

## Tech Stack

- **C** (69.9%) - Core algorithms and utility functions
- **C++** (24.2%) - High-level implementations
- **Python** (4.6%) - Analysis and visualization scripts
- **Makefile** (0.5%) - Build automation
- **Shell** (0.2%) - Utility scripts

## Build from Source

### Prerequisites

- GCC compiler (for C compilation)
- Make
- Standard C/C++ libraries

### Steps

1. **Clone the repository**
   ```sh
   git clone https://github.com/dash4k/jnatia-2026.git
   cd jnatia-2026
   ```

2. **Compile Utility Functions**
   ```sh
   cd utils/
   gcc -c util.c -o util.o
   cd ..
   ```

3. **Build Algorithms**
   ```sh
   make build
   ```

4. **Run Algorithms**
   ```sh
   make run
   ```

## Project Structure

```
jnatia-2026/
├── utils/           # Utility functions and helpers
├── src/             # Core source code
├── data/            # Test data and results
├── Makefile         # Build configuration
└── README.md        # This file
```

## Results

The comparative analysis produces output metrics for each signature algorithm, allowing researchers to evaluate the trade-offs between:

- Cryptographic security levels
- Visual quality preservation
- Embedding efficiency

## License

This project is part of academic research. For licensing details, please refer to the paper publication.

## Authors

- dash4k

## Acknowledgments

- JNATIA (Jurnal Nasional Teknologi Informasi dan Aplikasi)
- Universitas Udayana

---

*Last updated: 2026-07-28*
