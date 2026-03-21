import zipfile
import xml.etree.ElementTree as ET
import sys
import io

# Set stdout to UTF-8 for Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

def get_docx_text(path):
    """
    Extracts text from a .docx file by reading word/document.xml
    """
    try:
        with zipfile.ZipFile(path, 'r') as zip_ref:
            xml_content = zip_ref.read('word/document.xml')
            tree = ET.fromstring(xml_content)
            
            # Namespaces for Word XML
            ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
            
            paragraphs = []
            for p in tree.findall('.//w:p', ns):
                texts = [t.text for t in p.findall('.//w:t', ns) if t.text]
                if texts:
                    paragraphs.append("".join(texts))
            
            return "\n".join(paragraphs)
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    text = get_docx_text(r"C:\Users\User\Downloads\uber.docx")
    print(text)
