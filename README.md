</br>
<div align="center">
  <a href="https://www.unud.ac.id/">
    <img src="https://github.com/dash4k/tugas-akhir-alpro-1/assets/133938416/ff71757a-1b51-44b7-b14e-b53b061d9815" alt="Logo" width="230" height="259">
  </a>

<h1 align="center">Perbandingan Kualitas Visual Penyisipan Digital Signature Standards pada Game Sprite (PNG) Menggunakan Metode LSB Steganography</h1>

  <p align="center">
    Scripts for a comparative study measuring the visual-quality cost (PSNR, SSIM) of embedding RSA, Ed25519, and CRYSTALS-Dilithium digital signatures into PNG game sprites using LSB steganography, evaluating trade-offs as game studios consider post-quantum-ready asset authentication.
    </br>
  </p>
</div>
</br>

<h2 align="center">Build from source</h2>

1. Clone the repo
   ```sh
   git clone https://github.com/dash4k/snatia.git
   ```
2. Go to the build directory
   ```sh
   cd /snatia
   ```
3. Compile Utility Functions
   ```sh
   cd utils/ && gcc -c util.c -o util.o
   ```
4. Compile Algorithms
   ```sh
   cd ../ && make build
   ```
5. Run Algorithms
   ```sh
   make run
   ```
</br>
