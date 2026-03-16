from PIL import Image, ImageDraw, ImageFont
import os

def generate_banner():
    # Create a 1200x800 image with a deep space gradient
    width, height = 1200, 800
    base = Image.new('RGB', (width, height), (5, 5, 15))
    draw = ImageDraw.Draw(base)
    
    # Draw simple "Neural" patterns (lines)
    for i in range(0, width, 40):
        draw.line([(i, 0), (width-i, height)], fill=(30, 30, 60), width=1)
    
    # Text content (Using default font as we don't know path to ttf)
    try:
        # Drawing the 🌌 icon and name
        draw.text((width//2 - 100, height//2 - 100), "A U R A", fill=(0, 255, 255))
        draw.text((width//2 - 180, height//2), "THE SENTIENT OFFENSIVE ENGINE", fill=(200, 200, 255))
        draw.text((width//2 - 150, height//2 + 50), "[ OMEGA PROTOCOL ACTIVE ]", fill=(255, 0, 255))
    except:
        pass # Fallback to a simpler image if font fails

    banner_path = os.path.join(os.getcwd(), "aura_banner.png")
    base.save(banner_path)
    print(f"SUCCESS: Professional banner generated at {banner_path}")

if __name__ == "__main__":
    generate_banner()
