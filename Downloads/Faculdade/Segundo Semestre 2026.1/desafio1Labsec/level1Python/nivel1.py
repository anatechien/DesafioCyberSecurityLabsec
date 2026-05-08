import hashlib

output_size = 64  # 512 bits = 64 bytes

# Hash do PDF
with open("instructions.pdf", "rb") as f:
    pdf_bytes = f.read()

shake_pdf = hashlib.shake_256(pdf_bytes).digest(output_size)

# Hash da matrícula
matricula = "25205214".encode()
shake_mat = hashlib.shake_256(matricula).digest(output_size)

# XOR
resultado = bytes(a ^ b for a, b in zip(shake_pdf, shake_mat))

# Output final
print(resultado.hex())



