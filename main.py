from fastapi import FastAPI, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import random
import math
import os

from backend.lab1.lab1_logic import lcg_generate, test_cesaro, get_period, save_to_file, M
from backend.lab2.lab2_logic import md5_string, md5_bytes, save_result_to_file

from fastapi.responses import Response
from backend.lab3.lab3_logic import encrypt_file_data, decrypt_file_data

from backend.lab4.lab4_logic import generate_rsa_keys, rsa_encrypt_file, rsa_decrypt_file
import zipfile
import io
import urllib.parse

from backend.lab5.lab5_logic import generate_dsa_keys, dsa_sign_file, dsa_verify_file

app = FastAPI()


class Lab1Params(BaseModel):
    count: int


class Lab2TextParams(BaseModel):
    text: str



@app.post("/api/lab1/run")
def run_lab1(params: Lab1Params):
    if (params.count < 0):
        params.count = abs(params.count)
    custom_numbers = lcg_generate(count=params.count)
    os.makedirs("results", exist_ok=True)
    save_to_file("results/lab1_sequence.txt", custom_numbers)
    period = get_period()
    with open("results/lab1_period.txt", "w", encoding="utf-8") as f:
        f.write(f"Значення періоду функції генерації: {period}\n")
    pi_custom = test_cesaro(custom_numbers)
    sys_numbers = [random.randint(1, M) for _ in range(params.count)]
    pi_sys = test_cesaro(sys_numbers)
    pi_real = math.pi
    with open("results/lab1_cesaro_test.txt", "w", encoding="utf-8") as f:
        f.write(f"Кількість пар для тестування: {params.count // 2}\n")
        f.write(f"Значення Пі: {pi_real:.5f}\n")
        f.write(f"Оцінка Пі (Власний алгоритм): {pi_custom:.5f}\n")
        f.write(f"Оцінка Пі (Системний генератор): {pi_sys:.5f}\n\n")
    return {
        "total_generated": params.count,
        "period": period,
        "pi_custom": round(pi_custom, 5) if pi_custom else 0,
        "pi_sys": round(pi_sys, 5) if pi_sys else 0,
        "pi_real": round(math.pi, 5)
    }


@app.post("/api/lab2/hash_text")
def run_lab2_text(params: Lab2TextParams):
    res_hash = md5_string(params.text).upper()
    save_result_to_file("results/lab2_custom_text.txt", f"Text: {params.text}\nMD5: {res_hash}")
    return {"text": params.text, "hash": res_hash}


@app.post("/api/lab2/hash_file")
async def run_lab2_file(file: UploadFile = File(...), expected_hash: str = Form(default="")):
    content = await file.read()
    res_hash = md5_bytes(content).upper()
    is_valid = None
    if expected_hash:
        is_valid = (res_hash == expected_hash.strip().upper())

    report = f"File: {file.filename}\nHash: {res_hash}\nExpected: {expected_hash}\nValid: {is_valid}"
    save_result_to_file(f"results/lab2_file_{file.filename}.txt", report)

    return {
        "filename": file.filename,
        "hash": res_hash,
        "expected_hash": expected_hash.upper() if expected_hash else "",
        "is_valid": is_valid
    }


@app.post("/api/lab2/verify_with_file")
async def verify_lab2_with_file(target_file: UploadFile = File(...), hash_file: UploadFile = File(...)):
    content = await target_file.read()
    calculated_hash = md5_bytes(content).upper()

    hash_content = await hash_file.read()
    expected_hash = hash_content.decode('utf-8').strip().upper()

    is_valid = (calculated_hash == expected_hash)

    report = f"File: {target_file.filename}\nCalc: {calculated_hash}\nExpected: {expected_hash}\nValid: {is_valid}"
    save_result_to_file(f"results/lab2_verify_{target_file.filename}.txt", report)

    return {
        "filename": target_file.filename,
        "calculated_hash": calculated_hash,
        "expected_hash": expected_hash,
        "is_valid": is_valid
    }

@app.post("/api/lab2/run_tests")
def run_lab2_standard_tests():
    test_cases = [
        ("", "D41D8CD98F00B204E9800998ECF8427E"),
        ("a", "0CC175B9C0F1B6A831C399E269772661"),
        ("abc", "900150983CD24FB0D6963F7D28E17F72"),
        ("message digest", "F96B697D7CB7938D525A2F31AAF161D0"),
        ("abcdefghijklmnopqrstuvwxyz", "C3FCD3D76192E4007DFB496CCA67E13B"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "D174AB98D277D9F5A5611C2C9F419D9F"),
        ("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         "57EDF4A22BE3C955AC49DA2E2107B67A")
    ]
    results = []
    report_content = "Протокол тестування RFC 1321:\n\n"
    for text, expected in test_cases:
        actual = md5_string(text).upper()
        status = "OK" if actual == expected else "FAIL"
        line = f"Text: '{text}' -> Hash: {actual} [{status}]"
        results.append(line)
        report_content += line + "\n"

    save_result_to_file("results/lab2_standard_tests.txt", report_content)
    return {"results": results}

@app.post("/api/lab3/process")
async def process_lab3_file(
        file: UploadFile = File(...),
        pass_phrase: str = Form(...),
        w: int = Form(...),
        r: int = Form(...),
        b: int = Form(...),
        action: str = Form(...)
):
    content = await file.read()

    try:
        if action == "encrypt":
            result_data = encrypt_file_data(content, w, r, b, pass_phrase)
        else:
            result_data = decrypt_file_data(content, w, r, b, pass_phrase)

        return Response(content=result_data, media_type="application/octet-stream")
    except Exception as e:
        return Response(content=str(e), status_code=400)


@app.post("/api/lab4/generate_keys")
async def generate_keys_api():
    priv_pem, pub_pem = generate_rsa_keys(2048)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("private_key.pem", priv_pem)
        zip_file.writestr("public_key.pem", pub_pem)

    zip_buffer.seek(0)
    return Response(
        content=zip_buffer.read(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=rsa_keys.zip"}
    )


@app.post("/api/lab4/process")
async def process_lab4_file(
        file: UploadFile = File(...),
        key_file: UploadFile = File(...),
        action: str = Form(...)
):
    content = await file.read()
    key_content = await key_file.read()

    try:
        if action == "encrypt":
            result_data = rsa_encrypt_file(content, key_content)
            prefix = "enc_"
        else:
            result_data = rsa_decrypt_file(content, key_content)
            prefix = "dec_"

        return Response(
            content=result_data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={prefix}{file.filename}"}
        )
    except Exception as e:
        return Response(content=f"Помилка: {str(e)}", status_code=400)


@app.post("/api/lab5/generate_keys")
def generate_dsa_keys_api():
    try:
        priv_pem, pub_pem = generate_dsa_keys(2048)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr("dsa_private_key.pem", priv_pem)
            zip_file.writestr("dsa_public_key.pem", pub_pem)

        zip_buffer.seek(0)
        return Response(

            content=zip_buffer.read(),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=dsa_keys.zip"}
        )
    except Exception as e:
        return Response(content=f"Помилка генерації ключів: {str(e)}", status_code=400)

@app.post("/api/lab5/sign")
async def sign_lab5_file(file: UploadFile = File(...), key_file: UploadFile = File(...)):
    content = await file.read()
    key_content = await key_file.read()

    try:
        signature = dsa_sign_file(content, key_content)
        safe_filename = urllib.parse.quote(f"{file.filename}.sig")
        return Response(
            content=signature,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename*=utf-8''{safe_filename}"}
        )
    except Exception as e:
        return Response(content=f"Помилка створення підпису: {str(e)}", status_code=400)


@app.post("/api/lab5/verify")
async def verify_lab5_file(
        file: UploadFile = File(...),
        sig_file: UploadFile = File(...),
        key_file: UploadFile = File(...)
):
    content = await file.read()
    sig_content = await sig_file.read()
    key_content = await key_file.read()

    try:
        is_valid = dsa_verify_file(content, sig_content, key_content)
        if is_valid:
            return {"status": "success", "message": "Підпис ДІЙСНИЙ. Файл не був змінений і належить автору."}
        else:
            return {"status": "error", "message": "Підпис НЕДІЙСНИЙ. Файл пошкоджено або підписано іншим ключем."}
    except Exception as e:
        return {"status": "error", "message": f"Помилка перевірки: {str(e)}"}

app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")