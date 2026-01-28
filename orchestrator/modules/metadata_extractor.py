"""
Metadata Extraction Module
Extract EXIF data from images and metadata from PDFs
"""

import requests
import sqlite3
import json
import os
import tempfile
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from config import config

class MetadataExtractor:
    def __init__(self, target, target_id):
        self.target = target
        self.target_id = target_id
        self.extracted_metadata = []
    
    def find_images_on_page(self):
        """Find image URLs on target website"""
        images = []
        try:
            requests.packages.urllib3.disable_warnings()
            url = f"https://{self.target}"
            headers = {'User-Agent': config.USER_AGENT}
            res = requests.get(url, headers=headers, timeout=config.HTTP_TIMEOUT, verify=False)
            
            soup = BeautifulSoup(res.text, 'html.parser')
            
            for img in soup.find_all('img')[:10]:  # Limit to first 10 images
                img_url = img.get('src')
                if img_url:
                    # Convert relative URLs to absolute
                    full_url = urljoin(url, img_url)
                    images.append(full_url)
            
        except Exception as e:
            print(f"    [!] Failed to find images: {e}")
        
        return images
    
    def extract_exif_from_image(self, image_url):
        """Download image and extract EXIF data"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            
            # Download image
            headers = {'User-Agent': config.USER_AGENT}
            res = requests.get(image_url, headers=headers, timeout=10, verify=False)
            
            if res.status_code == 200 and 'image' in res.headers.get('Content-Type', '').lower():
                # Save to temp file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as tmp:
                    tmp.write(res.content)
                    tmp_path = tmp.name
                
                # Open with PIL and extract EXIF
                image = Image.open(tmp_path)
                exif_data = image._getexif()
                
                if exif_data:
                    metadata = {
                        'file_url': image_url,
                        'file_type': 'image',
                        'file_name': os.path.basename(urlparse(image_url).path)
                    }
                    
                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, tag_id)
                        
                        if tag == 'Make':
                            metadata['camera_make'] = str(value)
                        elif tag == 'Model':
                            metadata['camera_model'] = str(value)
                        elif tag == 'Software':
                            metadata['software'] = str(value)
                        elif tag == 'DateTime':
                            metadata['creation_date'] = str(value)
                        elif tag == 'GPSInfo':
                            # Extract GPS coordinates
                            gps_data = {}
                            for gps_tag in value:
                                gps_tag_name = GPSTAGS.get(gps_tag, gps_tag)
                                gps_data[gps_tag_name] = value[gps_tag]
                            
                            if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                                metadata['gps_latitude'] = self.convert_gps_to_decimal(gps_data['GPSLatitude'], gps_data.get('GPSLatitudeRef', 'N'))
                                metadata['gps_longitude'] = self.convert_gps_to_decimal(gps_data['GPSLongitude'], gps_data.get('GPSLongitudeRef', 'E'))
                    
                    metadata['raw_metadata'] = json.dumps({k: str(v) for k, v in exif_data.items() if k in TAGS})
                    
                    # Clean up temp file
                    image.close()
                    try:
                        os.unlink(tmp_path)
                    except: pass
                    
                    return metadata
                
                # Clean up
                image.close()
                try:
                    os.unlink(tmp_path)
                except: pass
                
        except Exception as e:
            print(f"    [!] EXIF extraction failed for {image_url}: {e}")
        
        return None
    
    def convert_gps_to_decimal(self, coord, ref):
        """Convert GPS coordinates to decimal format"""
        try:
            degrees = float(coord[0])
            minutes = float(coord[1])
            seconds = float(coord[2])
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            
            if ref in ['S', 'W']:
                decimal = -decimal
            
            return decimal
        except:
            return None
    
    def extract_pdf_metadata(self, pdf_url):
        """Download PDF and extract metadata"""
        try:
            from PyPDF2 import PdfReader
            import io
            
            headers = {'User-Agent': config.USER_AGENT}
            res = requests.get(pdf_url, headers=headers, timeout=10, verify=False)
            
            if res.status_code == 200 and 'pdf' in res.headers.get('Content-Type', '').lower():
                pdf_file = io.BytesIO(res.content)
                reader = PdfReader(pdf_file)
                
                metadata = reader.metadata
                if metadata:
                    return {
                        'file_url': pdf_url,
                        'file_type': 'pdf',
                        'file_name': os.path.basename(urlparse(pdf_url).path),
                        'author': metadata.get('/Author', ''),
                        'creator': metadata.get('/Creator', ''),
                        'producer': metadata.get('/Producer', ''),
                        'creation_date': metadata.get('/CreationDate', ''),
                        'modification_date': metadata.get('/ModDate', ''),
                        'raw_metadata': json.dumps({k: str(v) for k, v in metadata.items()})
                    }
        except Exception as e:
            print(f"    [!] PDF extraction failed for {pdf_url}: {e}")
        
        return None
    
    def store_metadata(self, metadata):
        """Store extracted metadata in database"""
        try:
            conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO metadata (target_id, file_url, file_type, file_name, author, creator, producer,
                                     creation_date, modification_date, gps_latitude, gps_longitude,
                                     camera_make, camera_model, software, raw_metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.target_id,
                metadata.get('file_url', ''),
                metadata.get('file_type', ''),
                metadata.get('file_name', ''),
                metadata.get('author', ''),
                metadata.get('creator', ''),
                metadata.get('producer', ''),
                metadata.get('creation_date', ''),
                metadata.get('modification_date', ''),
                metadata.get('gps_latitude'),
                metadata.get('gps_longitude'),
                metadata.get('camera_make', ''),
                metadata.get('camera_model', ''),
                metadata.get('software', ''),
                metadata.get('raw_metadata', '')
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"    [!] Database error: {e}")
    
    def execute(self):
        """Run complete metadata extraction"""
        print("[+] Running Metadata Extraction...")
        
        if not config.ENABLE_METADATA:
            print("    [!] Metadata extraction disabled in configuration")
            return
        
        # Find images on website
        print("    - Searching for images...")
        images = self.find_images_on_page()
        
        if not images:
            print("    [!] No images found")
            return
        
        print(f"    - Found {len(images)} images, extracting EXIF data...")
        
        extracted_count = 0
        
        for image_url in images[:5]:  # Limit to 5 images
            metadata = self.extract_exif_from_image(image_url)
            if metadata:
                extracted_count += 1
                
                # Display interesting findings
                if metadata.get('gps_latitude') and metadata.get('gps_longitude'):
                    print(f"      📍 GPS: {metadata['gps_latitude']}, {metadata['gps_longitude']}")
                    print(f"         From: {metadata.get('file_name', 'unknown')}")
                
                if metadata.get('camera_make'):
                    print(f"      📷 Camera: {metadata.get('camera_make')} {metadata.get('camera_model', '')}")
                
                if metadata.get('software'):
                    print(f"      💻 Software: {metadata.get('software')}")
                
                self.store_metadata(metadata)
        
        if extracted_count > 0:
            print(f"    - Extracted metadata from {extracted_count} files")
        else:
            print("    - No metadata found in images")
