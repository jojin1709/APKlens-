import os
import math
from PIL import Image, ImageDraw

def render_vector_icon():
    size = 1024
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 1. Base Squircle (Deep Obsidian #0c0e15 with smooth corners)
    margin = 32
    squircle_box = [margin, margin, size - margin, size - margin]
    rx = 224
    draw.rounded_rectangle(squircle_box, radius=rx, fill=(12, 14, 21, 255))
    # Bevel rim
    draw.rounded_rectangle(squircle_box, radius=rx, outline=(255, 255, 255, 45), width=6)

    # Center
    cx, cy = size // 2, int(size * 0.54)

    # 2. Android Antennae (Electric Cyan #00f5ff)
    ant_w = 48
    # Left antenna
    draw.line([(cx - 160, cy - 264), (cx - 248, cy - 400)], fill=(0, 245, 255, 255), width=ant_w)
    draw.ellipse([cx - 248 - ant_w//2, cy - 400 - ant_w//2, cx - 248 + ant_w//2, cy - 400 + ant_w//2], fill=(0, 245, 255, 255))
    draw.ellipse([cx - 160 - ant_w//2, cy - 264 - ant_w//2, cx - 160 + ant_w//2, cy - 264 + ant_w//2], fill=(0, 245, 255, 255))

    # Right antenna
    draw.line([(cx + 160, cy - 264), (cx + 248, cy - 400)], fill=(0, 245, 255, 255), width=ant_w)
    draw.ellipse([cx + 248 - ant_w//2, cy - 400 - ant_w//2, cx + 248 + ant_w//2, cy - 400 + ant_w//2], fill=(0, 245, 255, 255))
    draw.ellipse([cx + 160 - ant_w//2, cy - 264 - ant_w//2, cx + 160 + ant_w//2, cy - 264 + ant_w//2], fill=(0, 245, 255, 255))

    # 3. Outer Lens Ring (Pure Solid White - High contrast like Burp Suite)
    lens_r = 256
    ring_w = 60
    draw.ellipse([cx - lens_r, cy - lens_r, cx + lens_r, cy + lens_r], outline=(255, 255, 255, 255), width=ring_w)

    # 4. Precision Aperture Iris Blades (Cyan, Purple, Cobalt, Emerald)
    inner_r = lens_r - ring_w // 2
    # Draw 4 clean geometric pie-chords / arcs
    # Pie 1: Top-Right (Cyan)
    draw.pieslice([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r], start=270, end=360, fill=(0, 245, 255, 255))
    # Pie 2: Bottom-Right (Vivid Royal Purple)
    draw.pieslice([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r], start=0, end=90, fill=(176, 102, 255, 255))
    # Pie 3: Bottom-Left (Cobalt Blue)
    draw.pieslice([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r], start=90, end=180, fill=(37, 99, 235, 255))
    # Pie 4: Top-Left (Emerald Green)
    draw.pieslice([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r], start=180, end=270, fill=(0, 229, 163, 255))

    # 5. Core Focal Eye (Dark Void + White Optical Center)
    focal_r = 104
    draw.ellipse([cx - focal_r, cy - focal_r, cx + focal_r, cy + focal_r], fill=(12, 14, 21, 255), outline=(255, 255, 255, 255), width=20)
    pupil_r = 48
    draw.ellipse([cx - pupil_r, cy - pupil_r, cx + pupil_r, cy + pupil_r], fill=(0, 245, 255, 255))
    glint_r = 16
    draw.ellipse([cx + 16 - glint_r, cy - 16 - glint_r, cx + 16 + glint_r, cy - 16 + glint_r], fill=(255, 255, 255, 255))

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

    print("SUCCESS: Rendered clean vector PNG, Apple Touch Icon, and Favicon.ico successfully!")

render_vector_icon()
