from PIL import Image, ImageDraw, ImageFont
import os

s = 432
img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle([0, 0, s - 1, s - 1], radius=96, fill=(31, 56, 100, 255))
font_dir = os.path.join(os.environ.get("WINDIR", ""), "Fonts")
if not os.environ.get("WINDIR"):
    raise SystemExit("WINDIR not set")
font = ImageFont.truetype(os.path.join(font_dir, "arialbd.ttf"), 190)
text = "MR"
bbox = d.textbbox((0, 0), text, font=font)
w = bbox[2] - bbox[0]
h = bbox[3] - bbox[1]
d.text(((s - w) / 2 - bbox[0], (s - h) / 2 - bbox[1]), text, font=font, fill=(255, 255, 255, 255))
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "res", "mipmap-xxxhdpi", "ic_launcher.png")
os.makedirs(os.path.dirname(out), exist_ok=True)
img.save(out)
print(out, os.path.getsize(out))
