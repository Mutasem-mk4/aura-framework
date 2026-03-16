from PIL import Image, ImageDraw
import os

def generate_aura_logo():
    # 3:2 Ratio as requested by the platform (1500x1000)
    width, height = 1500, 1000
    # Deep Cyber-Noir background
    bg_color = (5, 5, 15) 
    image = Image.new('RGB', (width, height), bg_color)
    draw = ImageDraw.Draw(image)

    # 1. Draw "Neural Grid" background (very faint)
    for i in range(0, width, 50):
        draw.line([(i, 0), (i, height)], fill=(15, 15, 35), width=1)
    for i in range(0, height, 50):
        draw.line([(0, i), (width, i)], fill=(15, 15, 35), width=1)

    # 2. Draw Stylized geometric "A" (The Sovereign Mark)
    cx, cy = width // 2, height // 2
    size = 250
    # Triangle points
    top = (cx, cy - size)
    left = (cx - size, cy + size)
    right = (cx + size, cy + size)
    
    # Outer Glow Effect (Cyan)
    for offset in range(10, 0, -2):
        draw.line([top, left, right, top], fill=(0, 255, 255), width=offset)
    
    # Crossbar (The "Logic Bridge")
    bar_y = cy + 50
    draw.line([(cx - 150, bar_y), (cx + 150, bar_y)], fill=(255, 0, 255), width=8)
    
    # Secondary Glow (Magenta)
    draw.ellipse([cx - 10, bar_y - 10, cx + 10, bar_y + 10], fill=(255, 0, 255))

    # 3. Add text (A U R A) - Using lines to form letters for maximum compatibility
    def draw_text_lines(draw, start_x, start_y):
        # A
        draw.line([(start_x, start_y+40), (start_x+20, start_y), (start_x+40, start_y+40)], fill=(200, 200, 255), width=4)
        draw.line([(start_x+5, start_y+25), (start_x+35, start_y+25)], fill=(200, 200, 255), width=4)
        # U
        sx = start_x + 60
        draw.line([(sx, start_y), (sx, start_y+40), (sx+40, start_y+40), (sx+40, start_y)], fill=(200, 200, 255), width=4)
        # R
        sx = start_x + 120
        draw.line([(sx, start_y), (sx, start_y+40)], fill=(200, 200, 255), width=4)
        draw.line([(sx, start_y), (sx+40, start_y), (sx+40, start_y+20), (sx, start_y+20)], fill=(200, 200, 255), width=4)
        draw.line([(sx+20, start_y+20), (sx+40, start_y+40)], fill=(200, 200, 255), width=4)
        # A
        sx = start_x + 180
        draw.line([(sx, start_y+40), (sx+20, start_y), (sx+40, start_y+40)], fill=(200, 200, 255), width=4)
        draw.line([(sx+5, start_y+25), (sx+35, start_y+25)], fill=(200, 200, 255), width=4)

    draw_text_lines(draw, cx - 110, cy + size + 50)

    # 4. Save the Logo
    logo_path = os.path.join(os.getcwd(), "aura_logo.png")
    image.save(logo_path)
    print(f"SUCCESS: Aura Sovereign Logo generated at {logo_path}")

if __name__ == "__main__":
    generate_aura_logo()
