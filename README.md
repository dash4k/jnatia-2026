</br>
<div align="center">
  <a href="https://ejournal2.unud.ac.id/index.php/jnatia/en">
    <img width="4000" height="400" alt="pageHeaderLogoImage_en" src="https://github.com/user-attachments/assets/da25d3de-2d7c-4eca-bd8f-364de7eabc82" />
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
