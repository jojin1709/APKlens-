import os
from PIL import Image, ImageDraw

def render_android_lens_icon():
    # 1024x1024 canvas for crisp anti-aliasing
    size = 1024
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 1. Base Dark Squircle (Obsidian #0a0c12 like atomic.chat / macOS)
    margin = 32
    squircle_box = [margin, margin, size - margin, size - margin]
    rx = 224
    draw.rounded_rectangle(squircle_box, radius=rx, fill=(10, 12, 18, 255))
    # Inset subtle rim highlight
    draw.rounded_rectangle(squircle_box, radius=rx, outline=(255, 255, 255, 30), width=6)

    # 2. Official Android Green: #3DDC84 -> RGB (61, 220, 132)
    android_green = (61, 220, 132, 255)
    white = (255, 255, 255, 255)
    dark_void = (10, 12, 18, 255)
    electric_cyan = (0, 245, 255, 255)

    cx = size // 2
    # Baseline for Android head
    base_y = 660
    head_r = 310

    # Antennae
    ant_w = 48
    # Left antenna: from (cx - 165, base_y - 250) to (cx - 265, base_y - 430)
    draw.line([(cx - 160, base_y - 250), (cx - 265, base_y - 430)], fill=android_green, width=ant_w)
    draw.ellipse([cx - 265 - ant_w//2, base_y - 430 - ant_w//2, cx - 265 + ant_w//2, base_y - 430 + ant_w//2], fill=android_green)
    draw.ellipse([cx - 160 - ant_w//2, base_y - 250 - ant_w//2, cx - 160 + ant_w//2, base_y - 250 + ant_w//2], fill=android_green)

    # Right antenna: from (cx + 165, base_y - 250) to (cx + 265, base_y - 430)
    draw.line([(cx + 160, base_y - 250), (cx + 265, base_y - 430)], fill=android_green, width=ant_w)
    draw.ellipse([cx + 265 - ant_w//2, base_y - 430 - ant_w//2, cx + 265 + ant_w//2, base_y - 430 + ant_w//2], fill=android_green)
    draw.ellipse([cx + 160 - ant_w//2, base_y - 250 - ant_w//2, cx + 160 + ant_w//2, base_y - 250 + ant_w//2], fill=android_green)

    # Android Head Dome (Semicircle with flat bottom)
    # Chord from -180 to 0 (top half of circle)
    draw.chord([cx - head_r, base_y - head_r, cx + head_r, base_y + head_r], start=180, end=0, fill=android_green)

    # Rounded bottom corners on the head base
    bot_h = 32
    draw.rounded_rectangle([cx - head_r, base_y - bot_h, cx + head_r, base_y + 10], radius=16, fill=android_green)

    # 3. Eyes / Lens Integration
    # Left eye: Classic Android White Eye
    eye_y = base_y - 140
    left_eye_x = cx - 150
    eye_r = 34
    draw.ellipse([left_eye_x - eye_r, eye_y - eye_r, left_eye_x + eye_r, eye_y + eye_r], fill=white)

    # Right eye: Enlarged into the "APKLens" Cyber Camera Aperture!
    right_eye_x = cx + 140
    lens_outer_r = 95
    # Outer white ring
    draw.ellipse([right_eye_x - lens_outer_r, eye_y - lens_outer_r, right_eye_x + lens_outer_r, eye_y + lens_outer_r], outline=white, width=18, fill=dark_void)
    
    # Cyan aperture ring
    lens_inner_r = 68
    draw.ellipse([right_eye_x - lens_inner_r, eye_y - lens_inner_r, right_eye_x + lens_inner_r, eye_y + lens_inner_r], outline=electric_cyan, width=12)

    # Center optical focal point
    pupil_r = 26
    draw.ellipse([right_eye_x - pupil_r, eye_y - pupil_r, right_eye_x + pupil_r, eye_y + pupil_r], fill=electric_cyan)
    glint_r = 10
    draw.ellipse([right_eye_x + 8 - glint_r, eye_y - 8 - glint_r, right_eye_x + 8 + glint_r, eye_y - 8 + glint_r], fill=white)

    # Export paths
    public_dir = r"c:\Users\jojin\Downloads\APKLens\public"
    app_dir = r"c:\Users\jojin\Downloads\APKLens\app"

    # 512x512 PNG
    img_512 = img.resize((512, 512), Image.Resampling.LANCZOS)
    img_512.save(os.path.join(public_dir, "icon.png"), "PNG")
    img_512.save(os.path.join(public_dir, "apple-icon.png"), "PNG")
    img_512.save(os.path.join(app_dir, "apple-icon.png"), "PNG")

    # 180x180 touch icon
    img_180 = img.resize((180, 180), Image.Resampling.LANCZOS)
    img_180.save(os.path.join(public_dir, "apple-touch-icon.png"), "PNG")

    # Multi-resolution ICO (16, 32, 48, 64, 128, 256)
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(os.path.join(public_dir, "favicon.ico"), format="ICO", sizes=sizes)
    img.save(os.path.join(app_dir, "favicon.ico"), format="ICO", sizes=sizes)

    print("SUCCESS: Generated authentic Android-style APKLens icon set!")

render_android_lens_icon()
