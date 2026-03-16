from PIL import Image, ImageDraw, ImageFilter
import os
import math

def render_executive_logo():
    width, height = 1500, 1000
    # Create background with a subtle radial gradient feel
    image = Image.new('RGB', (width, height), (2, 6, 23))
    draw = ImageDraw.Draw(image)

    # 1. Subtle Radial Background Detail
    for i in range(1, 100):
        radius = 800 - i * 5
        color = (2 + i//5, 6 + i//4, 23 + i//2)
        draw.ellipse([width//2 - radius, height//2 - radius, 
                      width//2 + radius, height//2 + radius], 
                     outline=color, width=2)

    cx, cy = width // 2, height // 2 - 40
    
    # 2. The Faceted Monolith "A"
    # Facet 1: Left Wing (Deep Cobalt)
    left_wing = [(cx, cy - 200), (cx - 160, cy + 150), (cx, cy + 80)]
    draw.polygon(left_wing, fill=(30, 58, 138))
    
    # Facet 2: Right Wing (Bright Cobalt)
    right_wing = [(cx, cy - 200), (cx + 160, cy + 150), (cx, cy + 80)]
    draw.polygon(right_wing, fill=(59, 130, 246))
    
    # Facet 3: The Internal Logic Bridge (Titanium)
    bridge = [(cx - 60, cy + 30), (cx + 60, cy + 30), (cx, cy + 80)]
    draw.polygon(bridge, fill=(226, 232, 240))

    # 3. The "Sentient" Apex (Laser Cyan Glow)
    apex_size = 6
    draw.ellipse([cx - apex_size, cy - 200 - apex_size, 
                  cx + apex_size, cy - 200 + apex_size], 
                 fill=(34, 211, 238))
    
    # 4. Refined Typography (A U R A)
    # Using specific line geometry for ultra-clean look
    ty = cy + 280
    spacing = 120
    text_color = (248, 250, 252) # Ghost White
    
    def draw_letter(x, char):
        w, h = 60, 80
        if char == 'A':
            draw.line([(x, ty+h), (x+w//2, ty), (x+w, ty+h)], fill=text_color, width=4)
            draw.line([(x+w//4, ty+h//2+10), (x+3*w//4, ty+h//2+10)], fill=text_color, width=4)
        elif char == 'U':
            draw.line([(x, ty), (x, ty+h), (x+w, ty+h), (x+w, ty)], fill=text_color, width=4)
        elif char == 'R':
            draw.line([(x, ty), (x, ty+h)], fill=text_color, width=4)
            draw.line([(x, ty), (x+w-10, ty), (x+w, ty+h//4), (x+w-10, ty+h//2), (x, ty+h//2)], fill=text_color, width=4)
            draw.line([(x+w//2, ty+h//2), (x+w, ty+h)], fill=text_color, width=4)

    start_x = cx - (spacing * 1.5) - 30
    draw_letter(start_x, 'A')
    draw_letter(start_x + spacing, 'U')
    draw_letter(start_x + spacing*2, 'R')
    draw_letter(start_x + spacing*3, 'A')

    # 5. The "Sovereign" Subtitle
    sub_color = (100, 116, 139) # Slate Grey
    subtitle_y = ty + 130
    # Drawing a very clean horizontal separator
    draw.line([(cx - 250, subtitle_y), (cx + 250, subtitle_y)], fill=sub_color, width=1)

    # Final Save
    logo_path = os.path.join(os.getcwd(), "aura_logo_executive.png")
    image.save(logo_path)
    print(f"ULTIMATE VERSION COMPLETE: {logo_path}")

if __name__ == "__main__":
    render_executive_logo()
