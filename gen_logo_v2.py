from PIL import Image, ImageDraw
import os

def render_professional_logo():
    # 3:2 Ratio (1500x1000)
    width, height = 1500, 1000
    # Matte Obsidian Background
    image = Image.new('RGB', (width, height), (10, 10, 15))
    draw = ImageDraw.Draw(image)

    cx, cy = width // 2, height // 2
    
    # 1. The Hexagonal Shield (Refined Geometry)
    def get_hex_points(center_x, center_y, size):
        points = []
        for i in range(6):
            import math
            angle_deg = 60 * i - 30
            angle_rad = math.pi / 180 * angle_deg
            points.append((center_x + size * math.cos(angle_rad), 
                           center_y + size * math.sin(angle_rad)))
        return points

    # Draw Outer Shield (Slate Blue)
    shield_points = get_hex_points(cx, cy - 50, 220)
    draw.polygon(shield_points, outline=(74, 144, 226), width=12)
    
    # 2. The Stylized "A" (Negative Space Logic)
    # Drawing the "A" as two bold upward-pointing strokes
    a_size = 140
    # Left stroke
    draw.line([(cx - 80, cy + 50), (cx, cy - 120)], fill=(224, 224, 224), width=25)
    # Right stroke
    draw.line([(cx + 80, cy + 50), (cx, cy - 120)], fill=(224, 224, 224), width=25)
    # Horizontal Logic Bridge (Slate Blue accent)
    draw.line([(cx - 45, cy - 10), (cx + 45, cy - 10)], fill=(74, 144, 226), width=15)

    # 3. Minimalist Typography (A U R A)
    # We draw clean, thin-weight letters below the icon
    ty, tx = cy + 280, cx - 150
    # A
    draw.line([(tx, ty+60), (tx+25, ty), (tx+50, ty+60)], fill=(255, 255, 255), width=3)
    draw.line([(tx+8, ty+40), (tx+42, ty+40)], fill=(255, 255, 255), width=3)
    # U
    tx += 80
    draw.line([(tx, ty), (tx, ty+60), (tx+50, ty+60), (tx+50, ty)], fill=(255, 255, 255), width=3)
    # R
    tx += 80
    draw.line([(tx, ty), (tx, ty+60)], fill=(255, 255, 255), width=3)
    draw.line([(tx, ty), (tx+40, ty), (tx+50, ty+15), (tx+40, ty+30), (tx, ty+30)], fill=(255, 255, 255), width=3)
    draw.line([(tx+25, ty+30), (tx+50, ty+60)], fill=(255, 255, 255), width=3)
    # A
    tx += 80
    draw.line([(tx, ty+60), (tx+25, ty), (tx+50, ty+60)], fill=(255, 255, 255), width=3)
    draw.line([(tx+8, ty+40), (tx+42, ty+40)], fill=(255, 255, 255), width=3)

    # 4. Subtle Tagline
    tag_y = ty + 100
    # Center text approximately
    # "SOVEREIGN OFFENSIVE INTELLIGENCE"
    # (Represented by a very clean thin line indicating technical depth)
    draw.line([(cx - 200, tag_y), (cx + 200, tag_y)], fill=(40, 40, 60), width=2)

    # Save the Final Master
    logo_path = os.path.join(os.getcwd(), "aura_logo_professional.png")
    image.save(logo_path)
    print(f"MASTERPIECE READY: Professional logo saved to {logo_path}")

if __name__ == "__main__":
    render_professional_logo()
