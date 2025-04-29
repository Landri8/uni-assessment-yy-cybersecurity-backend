import random
import string
from captcha.image import ImageCaptcha
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import numpy as np
import os
from flask import url_for
from datetime import datetime
import io
import uuid
import cloudinary.uploader
import cloudinary

cloudinary.config(
    cloud_name="dwe12qajs",
    api_key="288736268681568",
    api_secret="OibV3PBgESVvCxNX90w2L-Nb4h4"
)

def generate_captcha_image(text):
    try: 
        unique_id = str(uuid.uuid4().hex)
    
        captcha = ImageCaptcha(width=280, height=90)
        image = captcha.generate_image(text)

        image = image.convert("RGB")
        draw = ImageDraw.Draw(image)

        for _ in range(1000):
            x, y = random.randint(0, image.width - 1), random.randint(0, image.height - 1)
            draw.point((x, y), fill="black")

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        filename = f"{unique_id}_{timestamp}.png"

        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format='PNG')
        img_byte_arr.seek(0) 
        upload_result = cloudinary.uploader.upload(img_byte_arr, public_id=filename)

        image_url = upload_result.get('secure_url')

        return image_url
    except Exception as e:
        raise(e)
