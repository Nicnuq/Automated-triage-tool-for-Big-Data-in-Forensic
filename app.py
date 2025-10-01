import os
import hashlib
import magic
import math
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
import logging
from typing import Dict, List
import numpy as np
from PIL import Image
import json

# Function to convert non-serialisable types to JSON
def make_json_serializable(obj):
    """Recursively converts objects to JSON-serializable types"""
    if isinstance(obj, dict):
        return {key: make_json_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [make_json_serializable(item) for item in obj]
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, bool):
        return obj  # Python booleans are normally OK
    else:
        return obj

# Configuration
class Config:
    """Centralized application configuration"""
    SECRET_KEY = 'forensic-triage-key-change-in-production'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 
                         'xls', 'xlsx', 'zip', 'rar', 'exe', 'dll', 'bat', 'ps1'}

# Initialisation Flask
app = Flask(__name__)
app.config.from_object(Config)

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create uploads folder
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

class ForensicScorer:
    """
    Classe principale pour le scoring forensique
    Basée sur les critères evidence-based de la recherche académique
    """
    
    # Suspicious extensions (based on DFRWS research)
    SUSPICIOUS_EXTENSIONS = {
        'exe', 'bat', 'cmd', 'com', 'scr', 'pif', 'vbs', 'js', 'jar',
        'dll', 'sys', 'drv', 'tmp', 'dmp'
    }
    
    # High forensic value extensions
    HIGH_VALUE_EXTENSIONS = {
        'pst', 'ost', 'edb', 'log', 'evtx', 'reg', 'dat', 'sqlite', 'db'
    }
    
    # Suspicious keywords in files
    SUSPICIOUS_KEYWORDS = {
        'password', 'crack', 'hack', 'exploit', 'backdoor', 'trojan',
        'virus', 'malware', 'keylog', 'steganography', 'hidden'
    }
    
    def __init__(self):
        """Initialize scorer with magic for MIME detection"""
        try:
            self.mime = magic.Magic(mime=True)
            self.magic_desc = magic.Magic()
        except Exception as e:
            logger.error(f"Magic initialization error: {e}")
            self.mime = None
            self.magic_desc = None
    
    def calculate_entropy(self, file_path: str, sample_size: int = 8192) -> float:
        """
        Calculates Shannon entropy of a file
        Values > 7.5 indicate encryption/compression (academic research)
        
        Args:
            file_path: Chemin vers le fichier
            sample_size: Taille de l'échantillon à analyser
            
        Returns:
            float: Shannon entropy (0-8)
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
            
            if not data:
                return 0.0
            
            # Calculate byte distribution
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate Shannon entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            logger.warning(f"Entropy calculation error for {file_path}: {e}")
            return 0.0
    
    def detect_steganography(self, file_path: str) -> Dict[str, any]:
        """
        Steganography detection through statistical analysis
        Based on Westfeld and Pfitzmann research
        
        Returns:
            Dict contenant les métriques de détection
        """
        try:
            file_ext = Path(file_path).suffix.lower().lstrip('.')
            file_size = os.path.getsize(file_path)
            
            stego_analysis = {
                'lsb_anomaly_score': 0,
                'entropy_variance': 0,
                'metadata_suspicion': 0,
                'size_complexity_ratio': 0,
                'is_suspicious': False,
                'techniques_detected': []
            }
            
            # 1. Specific analysis for images
            if file_ext in ['jpg', 'jpeg', 'png', 'bmp', 'gif']:
                stego_analysis.update(self._analyze_image_steganography(file_path))
            
            # 2. General file analysis
            stego_analysis.update(self._analyze_general_steganography(file_path, file_size))
            
            # 3. Final suspicion score
            total_score = (
                stego_analysis['lsb_anomaly_score'] +
                stego_analysis['entropy_variance'] +
                stego_analysis['metadata_suspicion'] +
                stego_analysis['size_complexity_ratio']
            )
            
            stego_analysis['total_suspicion_score'] = min(total_score, 100)
            stego_analysis['is_suspicious'] = total_score > 30
            
            return stego_analysis
            
        except Exception as e:
            logger.warning(f"Steganography detection error for {file_path}: {e}")
            return {
                'lsb_anomaly_score': 0,
                'entropy_variance': 0,
                'metadata_suspicion': 0,
                'size_complexity_ratio': 0,
                'total_suspicion_score': 0,
                'is_suspicious': False,
                'techniques_detected': [],
                'error': str(e)
            }
    
    def _analyze_image_steganography(self, file_path: str) -> Dict[str, any]:
        """Specific steganography analysis for images"""
        try:
            with Image.open(file_path) as img:
                # Convertir en RGB si nécessaire
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Convertir en array numpy
                img_array = np.array(img)
                
                results = {
                    'lsb_anomaly_score': 0,
                    'entropy_variance': 0,
                    'techniques_detected': []
                }
                
                # Test Chi-square pour LSB
                chi_square_score = self._chi_square_test(img_array)
                if chi_square_score > 0.05:  # Seuil de détection
                    results['lsb_anomaly_score'] = min(chi_square_score * 100, 50)
                    results['techniques_detected'].append('LSB_modification')
                
                # Analyse de variance d'entropie par blocs
                entropy_var = self._entropy_variance_analysis(img_array)
                if entropy_var > 0.3:  # Seuil d'anomalie
                    results['entropy_variance'] = min(entropy_var * 100, 30)
                    results['techniques_detected'].append('entropy_anomaly')
                
                # Test de Sample Pair Analysis (version simplifiée)
                spa_score = self._sample_pair_analysis(img_array)
                if spa_score > 0.1:
                    results['lsb_anomaly_score'] += min(spa_score * 50, 25)
                    if 'SPA_detection' not in results['techniques_detected']:
                        results['techniques_detected'].append('SPA_detection')
                
                return results
                
        except Exception as e:
            logger.warning(f"Image steganography analysis error: {e}")
            return {'lsb_anomaly_score': 0, 'entropy_variance': 0, 'techniques_detected': []}
    
    def _chi_square_test(self, img_array: np.ndarray) -> float:
        """Chi-square test to detect LSB modifications"""
        try:
            # Analyse uniquement le canal rouge pour simplifier
            red_channel = img_array[:, :, 0].flatten()
            
            # Compter les paires de valeurs consécutives
            pairs = {}
            for i in range(0, 256, 2):
                pairs[i] = np.sum(red_channel == i)
                pairs[i+1] = np.sum(red_channel == i+1)
            
            # Calculer le chi-square
            chi_square = 0
            for i in range(0, 256, 2):
                expected = (pairs[i] + pairs[i+1]) / 2
                if expected > 0:
                    chi_square += ((pairs[i] - expected) ** 2) / expected
                    chi_square += ((pairs[i+1] - expected) ** 2) / expected
            
            # Normaliser le score
            return min(chi_square / 1000, 1.0)
            
        except Exception:
            return 0.0
    
    def _entropy_variance_analysis(self, img_array: np.ndarray) -> float:
        """Entropy variance analysis by blocks"""
        try:
            height, width = img_array.shape[:2]
            block_size = 32
            entropies = []
            
            # Calculer l'entropie pour chaque bloc
            for i in range(0, height - block_size, block_size):
                for j in range(0, width - block_size, block_size):
                    block = img_array[i:i+block_size, j:j+block_size, 0]
                    hist, _ = np.histogram(block, bins=256, range=(0, 256))
                    hist = hist / hist.sum()
                    entropy = -np.sum(hist * np.log2(hist + 1e-10))
                    entropies.append(entropy)
            
            # Calculer la variance
            if len(entropies) > 1:
                variance = np.var(entropies)
                return min(variance / 10, 1.0)
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _sample_pair_analysis(self, img_array: np.ndarray) -> float:
        """Simplified version of Sample Pair Analysis"""
        try:
            red_channel = img_array[:, :, 0].flatten()
            
            # Compter les paires adjacentes
            same_lsb = 0
            diff_lsb = 0
            
            for i in range(len(red_channel) - 1):
                curr_lsb = red_channel[i] & 1
                next_lsb = red_channel[i+1] & 1
                
                if curr_lsb == next_lsb:
                    same_lsb += 1
                else:
                    diff_lsb += 1
            
            # Calculer le ratio (dans une image naturelle, le ratio devrait être équilibré)
            total_pairs = same_lsb + diff_lsb
            if total_pairs > 0:
                ratio = abs(same_lsb - diff_lsb) / total_pairs
                return min(ratio * 2, 1.0)
            
            return 0.0
            
        except Exception:
            return 0.0
    
    def _analyze_general_steganography(self, file_path: str, file_size: int) -> Dict[str, any]:
        """General steganography analysis for all file types"""
        try:
            results = {
                'metadata_suspicion': 0,
                'size_complexity_ratio': 0,
                'techniques_detected': []
            }
            
            # 1. Size vs complexity analysis
            entropy = self.calculate_entropy(file_path)
            if entropy > 7.8 and file_size > 1024:  # Très haute entropie
                complexity_score = (entropy - 7.5) * 20
                results['size_complexity_ratio'] = min(complexity_score, 40)
                results['techniques_detected'].append('high_entropy_payload')
            
            # 2. Metadata analysis (for certain formats)
            file_ext = Path(file_path).suffix.lower().lstrip('.')
            if file_ext in ['jpg', 'jpeg', 'png']:
                try:
                    with Image.open(file_path) as img:
                        # Vérifier les commentaires EXIF
                        if hasattr(img, '_getexif') and img._getexif():
                            exif_data = img._getexif()
                            if exif_data and len(str(exif_data)) > 1000:  # EXIF très volumineux
                                results['metadata_suspicion'] = 20
                                results['techniques_detected'].append('suspicious_metadata')
                except Exception:
                    pass
            
            # 3. Suspicious padding test
            with open(file_path, 'rb') as f:
                f.seek(-min(1024, file_size), 2)  # Lire les derniers 1024 bytes
                tail_data = f.read()
                
                # Chercher des patterns de padding suspects
                zero_ratio = tail_data.count(b'\x00') / len(tail_data)
                if zero_ratio > 0.9 and file_size > 10240:  # Beaucoup de zéros en fin
                    results['size_complexity_ratio'] += 15
                    results['techniques_detected'].append('suspicious_padding')
            
            return results
            
        except Exception as e:
            logger.warning(f"General steganography analysis error: {e}")
            return {'metadata_suspicion': 0, 'size_complexity_ratio': 0, 'techniques_detected': []}
    
    def analyze_timestamps(self, file_path: str) -> Dict[str, any]:
        """
        Analyzes NTFS timestamps to detect manipulations
        Based on Meridian Discovery research
        
        Returns:
            Dict contenant les métriques temporelles
        """
        try:
            stat = os.stat(file_path)
            
            created = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc)
            modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            accessed = datetime.fromtimestamp(stat.st_atime, tz=timezone.utc)
            
            # Détection d'anomalies temporelles
            anomalies = []
            
            # Modification antérieure à la création (copie de fichier)
            if modified < created:
                anomalies.append("modification_before_creation")
            
            # Timestamps arrondis (manipulation possible)
            if modified.microsecond == 0 and created.microsecond == 0:
                anomalies.append("rounded_timestamps")
            
            return {
                'created': created.isoformat(),
                'modified': modified.isoformat(),
                'accessed': accessed.isoformat(),
                'anomalies': anomalies,
                'anomaly_score': len(anomalies) * 10
            }
            
        except Exception as e:
            logger.warning(f"Timestamp analysis error for {file_path}: {e}")
            return {'anomaly_score': 0, 'anomalies': []}
    
    def detect_file_mismatch(self, file_path: str) -> bool:
        """
        Detects files with incorrect extensions
        Based on magic signature analysis
        """
        try:
            if not self.mime:
                return False
                
            file_ext = Path(file_path).suffix.lower().lstrip('.')
            mime_type = self.mime.from_file(file_path)
            
            # Mapping extension -> MIME attendu (étendu)
            expected_mimes = {
                'txt': ['text/plain', 'text/x-ascii'],
                'pdf': ['application/pdf'],
                'jpg': ['image/jpeg'],
                'jpeg': ['image/jpeg'],
                'png': ['image/png'],
                'gif': ['image/gif'],
                'exe': ['application/x-executable', 'application/x-dosexec', 'application/x-msdownload'],
                'dll': ['application/x-msdownload', 'application/x-executable'],
                'zip': ['application/zip'],
                'rar': ['application/x-rar-compressed'],
                'doc': ['application/msword'],
                'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
                'xls': ['application/vnd.ms-excel'],
                'xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
                'bat': ['text/plain', 'text/x-msdos-batch'],
                'ps1': ['text/plain']
            }
            
            if file_ext in expected_mimes:
                return mime_type not in expected_mimes[file_ext]
            
            return False
            
        except Exception as e:
            logger.warning(f"Mismatch detection error for {file_path}: {e}")
            return False
    
    def calculate_file_score(self, file_path: str) -> Dict[str, any]:
        """
        Calculates the global forensic score of a file
        5-level system: Bad (4), Suspicious (3), Unknown (2), Good (1), Notable (0)
        
        Returns:
            Dict avec score, niveau et détails de l'analyse
        """
        try:
            file_info = {
                'path': file_path,
                'name': os.path.basename(file_path),
                'size': os.path.getsize(file_path),
                'extension': Path(file_path).suffix.lower().lstrip('.'),
                'score': 0,
                'level': 'Good',
                'reasons': []
            }
            
            # 1. Metadata analysis
            timestamp_analysis = self.analyze_timestamps(file_path)
            file_info['timestamps'] = timestamp_analysis
            file_info['score'] += timestamp_analysis['anomaly_score']
            if timestamp_analysis['anomalies']:
                file_info['reasons'].extend([f"Timestamp anomaly: {a}" for a in timestamp_analysis['anomalies']])
            
            # 2. Extension analysis
            if file_info['extension'] in self.SUSPICIOUS_EXTENSIONS:
                file_info['score'] += 30
                file_info['reasons'].append(f"Suspicious extension: .{file_info['extension']}")
            
            if file_info['extension'] in self.HIGH_VALUE_EXTENSIONS:
                file_info['score'] += 20
                file_info['reasons'].append(f"High forensic value file: .{file_info['extension']}")
            
            # 3. Filename analysis
            filename_lower = file_info['name'].lower()
            for keyword in self.SUSPICIOUS_KEYWORDS:
                if keyword in filename_lower:
                    file_info['score'] += 25
                    file_info['reasons'].append(f"Suspicious keyword in name: {keyword}")
            
            # 4. Extension/content mismatch detection
            if self.detect_file_mismatch(file_path):
                file_info['score'] += 40
                file_info['reasons'].append("Extension does not match content")
            
            # 5. Entropy analysis (encryption indicator)
            entropy = self.calculate_entropy(file_path)
            file_info['entropy'] = round(entropy, 2)
            if entropy > 7.5:  # Seuil basé sur la recherche académique
                file_info['score'] += 35
                file_info['reasons'].append(f"High entropy ({entropy:.2f}) - Possible encryption")
            
            # 6. Steganography detection
            stego_analysis = self.detect_steganography(file_path)
            file_info['steganography'] = stego_analysis
            
            if stego_analysis['is_suspicious']:
                stego_score = min(stego_analysis['total_suspicion_score'], 40)
                file_info['score'] += stego_score
                
                techniques = stego_analysis.get('techniques_detected', [])
                if techniques:
                    file_info['reasons'].append(f"Steganography suspected: {', '.join(techniques)}")
                else:
                    file_info['reasons'].append("Steganography indicators detected")
            
            # 7. Size analysis (abnormally small/large files)
            size_mb = file_info['size'] / (1024 * 1024)
            if size_mb > 100:  # Files > 100MB
                file_info['score'] += 15
                file_info['reasons'].append(f"Large file: {size_mb:.1f}MB")
            elif file_info['size'] == 0:  # Empty files
                file_info['score'] += 10
                file_info['reasons'].append("Empty file")
            
            # 8. SHA-256 hash calculation (minimum research standard)
            try:
                sha256_hash = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(chunk)
                file_info['sha256'] = sha256_hash.hexdigest()
            except Exception as e:
                logger.warning(f"SHA-256 calculation error for {file_path}: {e}")
                file_info['sha256'] = 'ERROR'
            
            # 9. Score limitation to 100 points maximum
            file_info['score'] = min(file_info['score'], 100)
            
            # 10. Attribution du niveau final
            if file_info['score'] >= 80:
                file_info['level'] = 'Bad'
                file_info['level_num'] = 4
            elif file_info['score'] >= 50:
                file_info['level'] = 'Suspicious'
                file_info['level_num'] = 3
            elif file_info['score'] >= 20:
                file_info['level'] = 'Unknown'
                file_info['level_num'] = 2
            elif file_info['score'] > 0:
                file_info['level'] = 'Notable'
                file_info['level_num'] = 1
            else:
                file_info['level'] = 'Good'
                file_info['level_num'] = 0
            
            return file_info
            
        except Exception as e:
            logger.error(f"Scoring error for {file_path}: {e}")
            return {
                'path': file_path,
                'name': os.path.basename(file_path),
                'score': 0,
                'level': 'Unknown',
                'level_num': 2,
                'reasons': [f"Analysis error: {str(e)}"],
                'error': True
            }

class ForensicTriageSystem:
    """Système principal de triage forensique"""
    
    def __init__(self):
        self.scorer = ForensicScorer()
        self.results = []
    
    def analyze_directory(self, directory_path: str, max_files: int = 1000) -> List[Dict]:
        """
        Recursive directory analysis
        
        Args:
            directory_path: Chemin du répertoire à analyser
            max_files: Limite du nombre de fichiers (protection)
            
        Returns:
            Liste des résultats d'analyse
        """
        results = []
        file_count = 0
        
        try:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    if file_count >= max_files:
                        logger.warning(f"Limit of {max_files} files reached")
                        break
                    
                    file_path = os.path.join(root, file)
                    try:
                        result = self.scorer.calculate_file_score(file_path)
                        results.append(result)
                        file_count += 1
                    except Exception as e:
                        logger.warning(f"Analysis error {file_path}: {e}")
                        continue
                
                if file_count >= max_files:
                    break
            
            # Tri par score décroissant
            results.sort(key=lambda x: x.get('score', 0), reverse=True)
            
            logger.info(f"Analysis completed: {len(results)} files processed")
            return results
            
        except Exception as e:
            logger.error(f"Directory analysis error {directory_path}: {e}")
            return []
    
    def generate_summary(self, results: List[Dict]) -> Dict:
        """Generates a statistical summary of the analysis"""
        if not results:
            return {}
        
        df = pd.DataFrame(results)
        
        # Conversion explicite des types pandas en types Python natifs
        summary = {
            'total_files': int(len(results)),
            'levels_distribution': {k: int(v) for k, v in df['level'].value_counts().to_dict().items()},
            'avg_score': float(round(df['score'].mean(), 2)),
            'max_score': int(df['score'].max()),
            'high_risk_files': int(len(df[df['score'] >= 50])),
            'suspicious_extensions': {k: int(v) for k, v in df[df['extension'].isin(ForensicScorer.SUSPICIOUS_EXTENSIONS)]['extension'].value_counts().to_dict().items()},
            'high_entropy_files': int(len(df[df['entropy'] > 7.5])) if 'entropy' in df.columns else 0
        }
        
        return summary

# Instance globale
triage_system = ForensicTriageSystem()

# Routes Flask
@app.route('/')
def index():
    """Homepage with upload interface"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    """Endpoint for file upload and analysis"""
    try:
        logger.info(f"Upload request - Content-Type: {request.content_type}")
        logger.info(f"Form data: {request.form}")
        logger.info(f"Files: {request.files}")
        
        # Vérification plus robuste des fichiers
        if not request.files:
            return jsonify({'error': 'No files in request'}), 400
            
        files = request.files.getlist('files')
        if not files:
            return jsonify({'error': 'Empty file list'}), 400
        
        # Filtrer les fichiers vides et valides
        valid_files = []
        for f in files:
            if f and f.filename and f.filename.strip():
                # Vérifier que le fichier a du contenu
                f.seek(0, 2)  # Aller à la fin du fichier
                file_size = f.tell()
                f.seek(0)  # Revenir au début
                
                if file_size > 0 or f.filename.strip():  # Accepter même les fichiers vides s'ils ont un nom
                    valid_files.append(f)
                    
        if not valid_files:
            return jsonify({'error': 'No valid files selected'}), 400
        
        # Création d'un dossier unique pour cette analyse
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        analysis_dir = os.path.join(Config.UPLOAD_FOLDER, f'analysis_{timestamp}')
        os.makedirs(analysis_dir, exist_ok=True)
        
        # Sauvegarde des fichiers avec gestion des dossiers
        saved_files = []
        for file in valid_files:
            try:
                original_filename = file.filename
                filename = secure_filename(original_filename)
                
                if not filename:
                    filename = f"uploaded_file_{len(saved_files)}"
                
                # Gérer les chemins de dossiers (pour webkitdirectory)
                if '/' in original_filename or '\\' in original_filename:
                    # Créer la structure de dossiers
                    relative_path = original_filename.replace('\\', '/')
                    file_dir = os.path.dirname(relative_path)
                    filename = os.path.basename(relative_path)
                    
                    if file_dir:
                        full_dir = os.path.join(analysis_dir, secure_filename(file_dir.replace('/', '_')))
                        os.makedirs(full_dir, exist_ok=True)
                        file_path = os.path.join(full_dir, secure_filename(filename))
                    else:
                        file_path = os.path.join(analysis_dir, secure_filename(filename))
                else:
                    file_path = os.path.join(analysis_dir, filename)
                
                file.save(file_path)
                saved_files.append(file_path)
                logger.info(f"File saved: {file_path}")
            except Exception as e:
                logger.warning(f"Save error {original_filename}: {e}")
                continue
        
        if not saved_files:
            return jsonify({'error': 'No files could be saved'}), 400
        
        # Analyse forensique
        results = triage_system.analyze_directory(analysis_dir)
        summary = triage_system.generate_summary(results)

        # Conversion to avoid JSON serialization errors
        response_data = make_json_serializable({
            'success': True,
            'results': results,
            'summary': summary,
            'analysis_id': timestamp
        })

        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/results/<analysis_id>')
def get_results(analysis_id):
    """Retrieval of analysis results"""
    try:
        analysis_dir = os.path.join(Config.UPLOAD_FOLDER, f'analysis_{analysis_id}')
        if not os.path.exists(analysis_dir):
            return jsonify({'error': 'Analysis not found'}), 404
        
        results = triage_system.analyze_directory(analysis_dir)
        summary = triage_system.generate_summary(results)

        # Conversion to avoid JSON serialization errors
        response_data = make_json_serializable({
            'results': results,
            'summary': summary
        })

        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Results retrieval error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)