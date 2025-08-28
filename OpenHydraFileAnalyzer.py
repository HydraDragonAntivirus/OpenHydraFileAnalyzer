#!/usr/bin/env python3
"""
OpenHydraFileAnalyzer - PySide6 single-file application

A comprehensive file analysis tool with features for comparing, editing,
and analyzing binary files.

Features:
 - Dual-pane file loading (File A / File B) for comparison.
 - YARA-X rule loading, scanning, and a detailed match list.
 - Advanced YARA editor with syntax highlighting, saving, and validation.
 - CAPA integration for automated capability analysis with a structured match list.
 - CAPA rule editor with syntax highlighting.
 - yarGen integration with a full GUI to generate YARA rules from samples with meaningful names.
 - ClamAV SigTool integration for inspecting and decoding signature database files.
 - Computation and highlighting of differences (diff hunks) between files.
 - Interactive HTML-based hex panes with configurable bytes per row and grouping.
 - Light and Dark theme support.
 - Byte-level editing via a dialog or direct input controls.
 - Capstone-powered disassembly panes that update automatically after edits.
 - Navigation controls to jump between YARA matches.
 - Session persistence (saves last used file paths and settings).
 - DetectItEasy integration for packer/compiler identification.
 - Pefile-based feature extractor for detailed PE analysis, including GUI check.
 - Resource Viewer to inspect PE resources in a tree structure.
 - ML-ready YARA Rule Generator to create rules from extracted features.
"""

import sys
import os
import threading
import subprocess
import logging
import binascii
import json
import re
import hashlib
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont

# --- Dependency Checks and Imports ---

try:
    import yara_x
    YARA_AVAILABLE = True
except ImportError:
    yara_x = None
    YARA_AVAILABLE = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    np = None
    NUMPY_AVAILABLE = False


# --- Constants and Configuration ---

APP_NAME = "OpenHydraFileAnalyzer"
APP_VERSION = "0.1"
SETTINGS_FILE = "openhydra_settings.json"

BYTES_PER_ROW = 16
DEFAULT_CONTEXT_SIZE = 512
MIN_CONTEXT_SIZE = 128
MAX_CONTEXT_SIZE = 65536

# --- Default Paths (relative to script) ---
script_dir = os.path.dirname(os.path.abspath(__file__))
# Corrected CAPA rules directory to match user's setup
capa_rules_dir = os.path.join(script_dir, "capa-rules")
capa_results_dir = os.path.join(script_dir, "capa_results")
excluded_rules_dir = os.path.join(script_dir, "excluded-rules")


# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Syntax Highlighting Classes ---

class YaraHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for YARA rules."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569CD6"))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            "\\brule\\b", "\\bprivate\\b", "\\bglobal\\b", "\\bmeta\\b",
            "\\bstrings\\b", "\\bcondition\\b", "\\bimport\\b",
            "\\band\\b", "\\bor\\b", "\\bnot\\b", "\\bin\\b", "\\bat\\b",
            "\\bof\\b", "\\bfor\\b", "\\bany\\b", "\\ball\\b", "\\bthem\\b",
            "\\btrue\\b", "\\bfalse\\b",
            "\\bfilesize\\b", "\\bentrypoint\\b",
            "\\bint8\\b", "\\bint16\\b", "\\bint32\\b",
            "\\buint8\\b", "\\buint16\\b", "\\buint32\\b",
            "\\bint8be\\b", "\\bint16be\\b", "\\bint32be\\b",
            "\\buint8be\\b", "\\buint16be\\b", "\\buint32be\\b"
        ]
        self.highlighting_rules.extend([(QtCore.QRegularExpression(pattern), keyword_format) for pattern in keywords])

        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#D69D85"))
        self.highlighting_rules.append((QtCore.QRegularExpression("\".*\""), string_format))

        hex_string_format = QTextCharFormat()
        hex_string_format.setForeground(QColor("#B5CEA8"))
        self.highlighting_rules.append((QtCore.QRegularExpression("\\{.*\\}"), hex_string_format))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))
        self.highlighting_rules.append((QtCore.QRegularExpression("//[^\n]*"), comment_format))
        self.highlighting_rules.append((QtCore.QRegularExpression("/\\*.*\\*/"), comment_format))

        variable_format = QTextCharFormat()
        variable_format.setForeground(QColor("#9CDCFE"))
        self.highlighting_rules.append((QtCore.QRegularExpression("[$#@!][A-Za-z0-9_\\*]+"), variable_format))


    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = pattern
            it = expression.globalMatch(text)
            while it.hasNext():
                match = it.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)
        self.setCurrentBlockState(0)

class CapaHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for CAPA rules."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#C586C0"))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            "\\brule:\\b", "\\bmeta:\\b", "\\bfeatures:\\b",
            "\\band\\b", "\\bor\\b", "\\bnot\\b",
            "\\boptional:\\b", "\\bcount\\b", "\\bdescription:\\b",
            "\\bauthor:\\b", "\\bscope:\\b", "\\bexamples:\\b",
            "\\bfile\\b", "\\bfunction\\b", "\\bbasic block\\b"
        ]
        self.highlighting_rules.extend([(QtCore.QRegularExpression(pattern), keyword_format) for pattern in keywords])

        feature_format = QTextCharFormat()
        feature_format.setForeground(QColor("#4EC9B0"))
        features = [
            "\\bapi\\b", "\\bnumber\\b", "\\bstring\\b", "\\boffset\\b",
            "\\bbytes\\b", "\\bcharacteristic\\b", "\\bexport\\b",
            "\\bimport\\b", "\\bsection\\b", "\\bmatch\\b"
        ]
        self.highlighting_rules.extend([(QtCore.QRegularExpression(pattern), feature_format) for pattern in features])

        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#D69D85"))
        self.highlighting_rules.append((QtCore.QRegularExpression("\".*\""), string_format))
        self.highlighting_rules.append((QtCore.QRegularExpression("'.*'"), string_format))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))
        self.highlighting_rules.append((QtCore.QRegularExpression("#[^\n]*"), comment_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = pattern
            it = expression.globalMatch(text)
            while it.hasNext():
                match = it.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)
        self.setCurrentBlockState(0)

# --- PE Feature Extractor Class (Integrated) ---
class PEFeatureExtractor:
    def __init__(self):
        self.features_cache = {}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data or not NUMPY_AVAILABLE:
            return 0.0
        
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = counts / len(data)
        entropy = -np.sum(probabilities[probabilities > 0] * np.log2(probabilities[probabilities > 0]))
        return entropy

    def _calculate_md5(self, file_path: str) -> str:
        """Calculate MD5 hash of file."""
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()

    def extract_section_data(self, section) -> Dict[str, Any]:
        """Extract comprehensive section data including entropy."""
        raw_data = section.get_data()
        return {
            'name': section.Name.decode(errors='ignore').strip('\x00'),
            'virtual_size': section.Misc_VirtualSize,
            'virtual_address': section.VirtualAddress,
            'raw_size': section.SizeOfRawData,
            'pointer_to_raw_data': section.PointerToRawData,
            'characteristics': section.Characteristics,
            'entropy': self._calculate_entropy(raw_data),
            'raw_data_size': len(raw_data) if raw_data else 0
        }

    def extract_imports(self, pe) -> List[Dict[str, Any]]:
        """Extract detailed import information."""
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_imports = {
                    'dll_name': entry.dll.decode() if entry.dll else None,
                    'imports': [{
                        'name': imp.name.decode() if imp.name else None,
                        'address': imp.address,
                        'ordinal': imp.ordinal
                    } for imp in entry.imports]
                }
                imports.append(dll_imports)
        return imports

    def extract_exports(self, pe) -> List[Dict[str, Any]]:
        """Extract detailed export information."""
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    'name': exp.name.decode() if exp.name else None,
                    'address': exp.address,
                    'ordinal': exp.ordinal,
                    'forwarder': exp.forwarder.decode() if exp.forwarder else None
                }
                exports.append(export_info)
        return exports

    def analyze_tls_callbacks(self, pe) -> Dict[str, Any]:
        """Analyze TLS (Thread Local Storage) callbacks and extract relevant details."""
        try:
            tls_callbacks = {}
            # Check if the PE file has a TLS directory
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                tls = pe.DIRECTORY_ENTRY_TLS.struct
                tls_callbacks = {
                    'start_address_raw_data': tls.StartAddressOfRawData,
                    'end_address_raw_data': tls.EndAddressOfRawData,
                    'address_of_index': tls.AddressOfIndex,
                    'address_of_callbacks': tls.AddressOfCallBacks,
                    'size_of_zero_fill': tls.SizeOfZeroFill,
                    'characteristics': tls.Characteristics,
                    'callbacks': []
                }

                # If there are callbacks, extract their addresses
                if tls.AddressOfCallBacks:
                    callback_array = self._get_callback_addresses(pe, tls.AddressOfCallBacks)
                    if callback_array:
                        tls_callbacks['callbacks'] = callback_array

            return tls_callbacks
        except Exception as e:
            logging.error(f"Error analyzing TLS callbacks: {e}")
            return {}

    def _get_callback_addresses(self, pe, address_of_callbacks) -> List[int]:
        """Retrieve callback addresses from the TLS directory."""
        try:
            callback_addresses = []
            # Read callback addresses from the memory-mapped file
            while True:
                callback_address = pe.get_dword_at_rva(address_of_callbacks - pe.OPTIONAL_HEADER.ImageBase)
                if callback_address == 0:
                    break  # End of callback list
                callback_addresses.append(callback_address)
                address_of_callbacks += 4  # Move to the next address (4 bytes for DWORD)

            return callback_addresses
        except Exception as e:
            logging.error(f"Error retrieving TLS callback addresses: {e}")
            return []

    def analyze_dos_stub(self, pe) -> Dict[str, Any]:
        """Analyze DOS stub program."""
        try:
            dos_stub = {
                'exists': False,
                'size': 0,
                'entropy': 0.0,
            }

            if hasattr(pe, 'DOS_HEADER'):
                stub_offset = pe.DOS_HEADER.e_lfanew - 64  # Typical DOS stub starts after DOS header
                if stub_offset > 0:
                    dos_stub_data = pe.__data__[64:pe.DOS_HEADER.e_lfanew]
                    if dos_stub_data:
                        dos_stub['exists'] = True
                        dos_stub['size'] = len(dos_stub_data)
                        dos_stub['entropy'] = self._calculate_entropy(dos_stub_data)

            return dos_stub
        except Exception as e:
            logging.error(f"Error analyzing DOS stub: {e}")
            return {}

    def analyze_certificates(self, pe) -> Dict[str, Any]:
        """Analyze security certificates."""
        try:
            cert_info = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                cert_info['virtual_address'] = pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress
                cert_info['size'] = pe.DIRECTORY_ENTRY_SECURITY.Size

                # Extract certificate attributes if available
                if hasattr(pe, 'VS_FIXEDFILEINFO'):
                    cert_info['fixed_file_info'] = {
                        'signature': pe.VS_FIXEDFILEINFO.Signature,
                        'struct_version': pe.VS_FIXEDFILEINFO.StrucVersion,
                        'file_version': f"{pe.VS_FIXEDFILEINFO.FileVersionMS >> 16}.{pe.VS_FIXEDFILEINFO.FileVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO.FileVersionLS >> 16}.{pe.VS_FIXEDFILEINFO.FileVersionLS & 0xFFFF}",
                        'product_version': f"{pe.VS_FIXEDFILEINFO.ProductVersionMS >> 16}.{pe.VS_FIXEDFILEINFO.ProductVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO.ProductVersionLS >> 16}.{pe.VS_FIXEDFILEINFO.ProductVersionLS & 0xFFFF}",
                        'file_flags': pe.VS_FIXEDFILEINFO.FileFlags,
                        'file_os': pe.VS_FIXEDFILEINFO.FileOS,
                        'file_type': pe.VS_FIXEDFILEINFO.FileType,
                        'file_subtype': pe.VS_FIXEDFILEINFO.FileSubtype,
                    }

            return cert_info
        except Exception as e:
            logging.error(f"Error analyzing certificates: {e}")
            return {}

    def analyze_delay_imports(self, pe) -> List[Dict[str, Any]]:
        """Analyze delay-load imports with error handling for missing attributes."""
        try:
            delay_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    imports = []
                    for imp in entry.imports:
                        import_info = {
                            'name': imp.name.decode() if imp.name else None,
                            'address': imp.address,
                            'ordinal': imp.ordinal,
                        }
                        imports.append(import_info)

                    delay_import = {
                        'dll': entry.dll.decode() if entry.dll else None,
                        'attributes': getattr(entry.struct, 'Attributes', None),  # Use getattr for safe access
                        'name': getattr(entry.struct, 'Name', None),
                        'handle': getattr(entry.struct, 'Handle', None),
                        'iat': getattr(entry.struct, 'IAT', None),
                        'bound_iat': getattr(entry.struct, 'BoundIAT', None),
                        'unload_iat': getattr(entry.struct, 'UnloadIAT', None),
                        'timestamp': getattr(entry.struct, 'TimeDateStamp', None),
                        'imports': imports
                    }
                    delay_imports.append(delay_import)

            return delay_imports
        except Exception as e:
            logging.error(f"Error analyzing delay imports: {e}")
            return []

    def analyze_load_config(self, pe) -> Dict[str, Any]:
        """Analyze load configuration."""
        try:
            load_config = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                load_config = {
                    'size': config.Size,
                    'timestamp': config.TimeDateStamp,
                    'major_version': config.MajorVersion,
                    'minor_version': config.MinorVersion,
                    'global_flags_clear': config.GlobalFlagsClear,
                    'global_flags_set': config.GlobalFlagsSet,
                    'critical_section_default_timeout': config.CriticalSectionDefaultTimeout,
                    'decommit_free_block_threshold': config.DeCommitFreeBlockThreshold,
                    'decommit_total_free_threshold': config.DeCommitTotalFreeThreshold,
                    'security_cookie': config.SecurityCookie,
                    'se_handler_table': config.SEHandlerTable,
                    'se_handler_count': config.SEHandlerCount
                }

            return load_config
        except Exception as e:
            logging.error(f"Error analyzing load config: {e}")
            return {}

    def analyze_relocations(self, pe) -> List[Dict[str, Any]]:
        """Analyze base relocations with summarized entries."""
        try:
            relocations = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                    # Summarize relocation entries
                    entry_types = {}
                    offsets = []

                    for entry in base_reloc.entries:
                        entry_types[entry.type] = entry_types.get(entry.type, 0) + 1
                        offsets.append(entry.rva - base_reloc.struct.VirtualAddress)

                    reloc_info = {
                        'virtual_address': base_reloc.struct.VirtualAddress,
                        'size_of_block': base_reloc.struct.SizeOfBlock,
                        'summary': {
                            'total_entries': len(base_reloc.entries),
                            'types': entry_types,  # Counts of each relocation type
                            'offset_range': (min(offsets), max(offsets)) if offsets else None
                        }
                    }

                    relocations.append(reloc_info)

            return relocations
        except Exception as e:
            logging.error(f"Error analyzing relocations: {e}")
            return []

    def analyze_bound_imports(self, pe) -> List[Dict[str, Any]]:
        """Analyze bound imports with robust error handling."""
        try:
            bound_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
                for bound_imp in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                    bound_import = {
                        'name': bound_imp.name.decode() if bound_imp.name else None,
                        'timestamp': bound_imp.struct.TimeDateStamp,
                        'references': []
                    }

                    # Check if `references` exists
                    if hasattr(bound_imp, 'references') and bound_imp.references:
                        for ref in bound_imp.references:
                            reference = {
                                'name': ref.name.decode() if ref.name else None,
                                'timestamp': getattr(ref.struct, 'TimeDateStamp', None)
                            }
                            bound_import['references'].append(reference)
                    else:
                        logging.warning(f"Bound import {bound_import['name']} has no references.")

                    bound_imports.append(bound_import)

            return bound_imports
        except Exception as e:
            logging.error(f"Error analyzing bound imports: {e}")
            return []

    def analyze_section_characteristics(self, pe) -> Dict[str, Dict[str, Any]]:
        """Analyze detailed section characteristics."""
        try:
            characteristics = {}
            for section in pe.sections:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
                flags = section.Characteristics

                # Decode section characteristics flags
                section_flags = {
                    'CODE': bool(flags & 0x20),
                    'INITIALIZED_DATA': bool(flags & 0x40),
                    'UNINITIALIZED_DATA': bool(flags & 0x80),
                    'MEM_DISCARDABLE': bool(flags & 0x2000000),
                    'MEM_NOT_CACHED': bool(flags & 0x4000000),
                    'MEM_NOT_PAGED': bool(flags & 0x8000000),
                    'MEM_SHARED': bool(flags & 0x10000000),
                    'MEM_EXECUTE': bool(flags & 0x20000000),
                    'MEM_READ': bool(flags & 0x40000000),
                    'MEM_WRITE': bool(flags & 0x80000000)
                }

                characteristics[section_name] = {
                    'flags': section_flags,
                    'entropy': self._calculate_entropy(section.get_data()),
                    'size_ratio': section.SizeOfRawData / pe.OPTIONAL_HEADER.SizeOfImage if pe.OPTIONAL_HEADER.SizeOfImage else 0,
                    'pointer_to_raw_data': section.PointerToRawData,
                    'pointer_to_relocations': section.PointerToRelocations,
                    'pointer_to_line_numbers': section.PointerToLinenumbers,
                    'number_of_relocations': section.NumberOfRelocations,
                    'number_of_line_numbers': section.NumberOfLinenumbers,
                }

            return characteristics
        except Exception as e:
            logging.error(f"Error analyzing section characteristics: {e}")
            return {}

    def analyze_extended_headers(self, pe) -> Dict[str, Any]:
        """Analyze extended header information."""
        try:
            headers = {
                'dos_header': {
                    'e_magic': pe.DOS_HEADER.e_magic,
                    'e_cblp': pe.DOS_HEADER.e_cblp,
                    'e_cp': pe.DOS_HEADER.e_cp,
                    'e_crlc': pe.DOS_HEADER.e_crlc,
                    'e_cparhdr': pe.DOS_HEADER.e_cparhdr,
                    'e_minalloc': pe.DOS_HEADER.e_minalloc,
                    'e_maxalloc': pe.DOS_HEADER.e_maxalloc,
                    'e_ss': pe.DOS_HEADER.e_ss,
                    'e_sp': pe.DOS_HEADER.e_sp,
                    'e_csum': pe.DOS_HEADER.e_csum,
                    'e_ip': pe.DOS_HEADER.e_ip,
                    'e_cs': pe.DOS_HEADER.e_cs,
                    'e_lfarlc': pe.DOS_HEADER.e_lfarlc,
                    'e_ovno': pe.DOS_HEADER.e_ovno,
                    'e_oemid': pe.DOS_HEADER.e_oemid,
                    'e_oeminfo': pe.DOS_HEADER.e_oeminfo
                },
                'nt_headers': {}
            }

            # Ensure NT_HEADERS exists and contains FileHeader
            if hasattr(pe, 'NT_HEADERS') and pe.NT_HEADERS is not None:
                nt_headers = pe.NT_HEADERS
                if hasattr(nt_headers, 'FileHeader'):
                    headers['nt_headers'] = {
                        'signature': nt_headers.Signature,
                        'machine': nt_headers.FileHeader.Machine,
                        'number_of_sections': nt_headers.FileHeader.NumberOfSections,
                        'time_date_stamp': nt_headers.FileHeader.TimeDateStamp,
                        'characteristics': nt_headers.FileHeader.Characteristics
                    }

            return headers
        except Exception as e:
            logging.error(f"Error analyzing extended headers: {e}")
            return {}

    def serialize_data(self, data) -> Any:
        """Serialize data for output, ensuring compatibility."""
        try:
            return list(data) if data else None
        except Exception:
            return None

    def analyze_rich_header(self, pe) -> Dict[str, Any]:
        """Analyze Rich header details."""
        try:
            rich_header = {}
            if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER is not None:
                rich_header['checksum'] = getattr(pe.RICH_HEADER, 'checksum', None)
                rich_header['values'] = self.serialize_data(pe.RICH_HEADER.values)
                rich_header['clear_data'] = self.serialize_data(pe.RICH_HEADER.clear_data)
                rich_header['key'] = self.serialize_data(pe.RICH_HEADER.key)
                rich_header['raw_data'] = self.serialize_data(pe.RICH_HEADER.raw_data)

                # Decode CompID and build number information
                compid_info = []
                for i in range(0, len(pe.RICH_HEADER.values), 2):
                    if i + 1 < len(pe.RICH_HEADER.values):
                        comp_id = pe.RICH_HEADER.values[i] >> 16
                        build_number = pe.RICH_HEADER.values[i] & 0xFFFF
                        count = pe.RICH_HEADER.values[i + 1]
                        compid_info.append({
                            'comp_id': comp_id,
                            'build_number': build_number,
                            'count': count
                        })
                rich_header['comp_id_info'] = compid_info

            return rich_header
        except Exception as e:
            logging.error(f"Error analyzing Rich header: {e}")
            return {}

    def analyze_overlay(self, pe, file_path: str) -> Dict[str, Any]:
        """Analyze file overlay (data appended after the PE structure)."""
        try:
            overlay_info = {
                'exists': False,
                'offset': 0,
                'size': 0,
                'entropy': 0.0
            }

            # Calculate the end of the PE structure
            last_section = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
            end_of_pe = last_section.PointerToRawData + last_section.SizeOfRawData

            # Get file size
            file_size = os.path.getsize(file_path)

            # Check for overlay
            if file_size > end_of_pe:
                with open(file_path, 'rb') as f:
                    f.seek(end_of_pe)
                    overlay_data = f.read()

                    overlay_info['exists'] = True
                    overlay_info['offset'] = end_of_pe
                    overlay_info['size'] = len(overlay_data)
                    overlay_info['entropy'] = self._calculate_entropy(overlay_data)

            return overlay_info
        except Exception as e:
            logging.error(f"Error analyzing overlay: {e}")
            return {}

    def extract_numeric_features(self, file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Extract numeric features of a file using pefile.
        """
        try:
            # Load the PE file
            pe = pefile.PE(file_path)

            # Extract features
            numeric_features = {
                # Optional Header Features
                'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
                'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
                'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
                'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
                'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
                'BaseOfData': getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0),
                'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
                'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
                'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
                'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
                'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
                'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
                'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
                'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
                'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
                'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
                'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
                'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
                'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
                'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,

                # Section Headers
                'sections': [
                    {
                        'name': section.Name.decode(errors='ignore').strip('\x00'),
                        'virtual_size': section.Misc_VirtualSize,
                        'virtual_address': section.VirtualAddress,
                        'size_of_raw_data': section.SizeOfRawData,
                        'pointer_to_raw_data': section.PointerToRawData,
                        'characteristics': section.Characteristics,
                    }
                    for section in pe.sections
                ],

                # Imported Functions
                'imports': [
                    imp.name.decode(errors='ignore') if imp.name else "Unknown"
                    for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
                    for imp in getattr(entry, 'imports', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],

                # Exported Functions
                'exports': [
                    exp.name.decode(errors='ignore') if exp.name else "Unknown"
                    for exp in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [],

                # Resources
                'resources': [
                    {
                        'type_id': getattr(getattr(resource_type, 'struct', None), 'Id', None),
                        'resource_id': getattr(getattr(resource_id, 'struct', None), 'Id', None),
                        'lang_id': getattr(getattr(resource_lang, 'struct', None), 'Id', None),
                        'size': getattr(getattr(resource_lang, 'data', None), 'Size', None),
                        'codepage': getattr(getattr(resource_lang, 'data', None), 'CodePage', None),
                    }
                    for resource_type in
                    (pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries') else [])
                    for resource_id in (resource_type.directory.entries if hasattr(resource_type, 'directory') else [])
                    for resource_lang in (resource_id.directory.entries if hasattr(resource_id, 'directory') else [])
                    if hasattr(resource_lang, 'data')
                ] if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else [],

                # Debug Information
                'debug': [
                    {
                        'type': debug.struct.Type,
                        'timestamp': debug.struct.TimeDateStamp,
                        'version': f"{debug.struct.MajorVersion}.{debug.struct.MinorVersion}",
                        'size': debug.struct.SizeOfData,
                    }
                    for debug in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else [],

                # Certificates
                'certificates': self.analyze_certificates(pe),  # Analyze certificates

                # DOS Stub Analysis
                'dos_stub': self.analyze_dos_stub(pe),  # DOS stub analysis here

                # TLS Callbacks
                'tls_callbacks': self.analyze_tls_callbacks(pe),  # TLS callback analysis here

                # Delay Imports
                'delay_imports': self.analyze_delay_imports(pe),  # Delay imports analysis here

                # Load Config
                'load_config': self.analyze_load_config(pe),  # Load config analysis here

                # Bound Imports
                'bound_imports': self.analyze_bound_imports(pe),  # Bound imports analysis here

                # Section Characteristics
                'section_characteristics': self.analyze_section_characteristics(pe),
                # Section characteristics analysis here

                # Extended Headers
                'extended_headers': self.analyze_extended_headers(pe),  # Extended headers analysis here

                # Rich Header
                'rich_header': self.analyze_rich_header(pe),  # Rich header analysis here

                # Overlay
                'overlay': self.analyze_overlay(pe, file_path),  # Overlay analysis here
                
                #Relocations
                'relocations': self.analyze_relocations(pe) #Relocations analysis here
            }

            # Add numeric tag if provided
            if rank is not None:
                numeric_features['numeric_tag'] = rank

            return numeric_features

        except Exception as ex:
            logging.error(f"Error extracting numeric features from {file_path}: {str(ex)}", exc_info=True)
            return None

# --- Helper Functions ---

def compute_diff_hunks(a: bytes, b: bytes) -> List[Dict[str, int]]:
    """Computes differences between two byte strings."""
    hunks = []
    if a is None or b is None:
        return hunks
    la, lb = len(a), len(b)
    lmin = min(la, lb)
    i = 0
    in_diff = False
    diff_start = 0
    while i < lmin:
        if a[i] != b[i]:
            if not in_diff:
                in_diff = True
                diff_start = i
        else:
            if in_diff:
                hunks.append({"start": diff_start, "length": i - diff_start})
                in_diff = False
        i += 1
    if in_diff:
        hunks.append({"start": diff_start, "length": i - diff_start})
    if la != lb:
        hunks.append({"start": lmin, "length": abs(la - lb)})
    return hunks

def intervals_from_matches(matches: List[Dict[str, Any]]) -> List[Tuple[int, int]]:
    """Creates a list of start/end intervals from YARA matches."""
    ivals = []
    for m in matches:
        start = m.get("offset", 0)
        end = start + max(0, m.get("length", 0)) - 1
        if end >= start:
            ivals.append((start, end))
    return ivals

def interval_contains(intervals: List[Tuple[int, int]], pos: int) -> bool:
    """Checks if a position is within any of the given intervals."""
    for s, e in intervals:
        if s <= pos <= e:
            return True
    return False

def collect_yara_matches(rules_path: str, data: bytes, excluded_rules: set) -> List[Dict[str, Any]]:
    """Compiles YARA-X rules and runs them against data, returning structured match info."""
    out = []
    if not YARA_AVAILABLE:
        logging.warning("YARA-X Python library not found. Please run: pip install yara-x")
        return out
    if not rules_path or data is None:
        return out

    try:
        with open(rules_path, 'r', encoding='utf-8', errors='ignore') as f:
            rules_content = f.read()
        rules = yara_x.compile(rules_content)
    except (IOError, yara_x.CompileError) as e:
        logging.error(f"YARA-X compile error: {e}")
        raise

    scanner = yara_x.Scanner(rules)
    matches = scanner.scan(data)
    
    for m in matches.matching_rules:
        if m.identifier in excluded_rules:
            continue
        for p in m.patterns:
            for inst in p.matches:
                out.append({
                    "rule_name": m.identifier,
                    "identifier": p.identifier,
                    "offset": inst.offset,
                    "length": inst.length,
                    "data": data[inst.offset : inst.offset + inst.length]
                })
    return out


def parse_capa_output(capa_text: str) -> List[Dict[str, Any]]:
    """Parses the text output from CAPA into a structured list of matches."""
    matches = []
    pattern = re.compile(r"^(.*)\s\(\d+\smatches?\)\s@\s(.*)$")
    for line in capa_text.splitlines():
        match = pattern.match(line.strip())
        if match:
            capability = match.group(1).strip()
            addrs_str = match.group(2).strip()
            addresses = [int(addr.strip(), 16) for addr in addrs_str.split(',')]
            for addr in addresses:
                matches.append({'capability': capability, 'address': addr})
    return matches

def run_capa_analysis(file_path: str, capa_exe_path: str = "capa.exe") -> Optional[str]:
    """
    Runs CAPA analysis on a file and saves the results to a unique directory.
    """
    if not os.path.exists(file_path):
        logging.error(f"CAPA analysis target not found: {file_path}")
        return None
        
    if not os.path.exists(capa_rules_dir):
        logging.error(f"CAPA rules directory not found at: {capa_rules_dir}")
        return None

    try:
        logging.info(f"Running CAPA analysis on: {file_path}")
        os.makedirs(capa_results_dir, exist_ok=True)
        
        folder_number = 1
        while os.path.exists(os.path.join(capa_results_dir, str(folder_number))):
            folder_number += 1
        capa_output_dir = os.path.join(capa_results_dir, str(folder_number))
        os.makedirs(capa_output_dir)

        base_name = Path(file_path).stem
        txt_output_file = os.path.join(capa_output_dir, f"{base_name}_capa_results.txt")

        capa_command = [capa_exe_path, "-r", capa_rules_dir, "-v", file_path]
        
        logging.info(f"Executing: {' '.join(capa_command)}")
        result = subprocess.run(
            capa_command, check=True, capture_output=True, text=True, encoding='utf-8', errors='ignore'
        )

        with open(txt_output_file, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        logging.info(f"CAPA results saved to: {txt_output_file}")
        return txt_output_file

    except FileNotFoundError:
        logging.error(f"capa.exe not found at path: {capa_exe_path}")
        return None
    except subprocess.CalledProcessError as ex:
        logging.error(f"CAPA analysis failed for {file_path}: {ex}")
        logging.error(f"CAPA stderr: {ex.stderr}")
        error_file = os.path.join(capa_output_dir, f"{base_name}_capa_error.txt")
        with open(error_file, "w", encoding="utf-8") as f:
            f.write(f"CAPA Error for {file_path}\nReturn code: {ex.returncode}\n\nSTDOUT:\n{ex.stdout}\n\nSTDERR:\n{ex.stderr}\n")
        logging.info(f"Error details saved to: {error_file}")
        return None
    except Exception as ex:
        logging.error(f"An unexpected error occurred during CAPA analysis on {file_path}: {ex}")
        return None

# --- Main Application Window ---

class OpenHydraFileAnalyzer(QtWidgets.QMainWindow):
    """The main window for the OpenHydraFileAnalyzer application."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setWindowIcon(self.style().standardIcon(QtWidgets.QStyle.SP_ComputerIcon))
        self.resize(1600, 1000)

        # --- Application State ---
        self.settings = self.load_settings()
        self.is_dark_theme = self.settings.get("dark_theme", False)
        
        self.file_a_path: Optional[str] = self.settings.get("file_a_path")
        self.file_b_path: Optional[str] = self.settings.get("file_b_path")
        self.yara_path: Optional[str] = self.settings.get("yara_path")
        self.excluded_rules = set()

        
        self.file_a_data: Optional[bytearray] = None
        self.file_b_data: Optional[bytearray] = None
        
        self.pe_features_a: Optional[Dict] = None
        self.pe_features_b: Optional[Dict] = None

        self.matches_a: List[Dict] = []
        self.matches_b: List[Dict] = []
        self.capa_matches: List[Tuple[str, Dict]] = [] # e.g. [('A', {'cap': '...', 'addr': ...})]
        self.diff_hunks: List[Dict] = []
        self.yara_index: Dict = {}
        self._yara_keys: List = []

        self.match_idx_a: int = -1
        self.match_idx_b: int = -1
        
        self.show_diff: bool = True
        self.context: int = self.settings.get("context", DEFAULT_CONTEXT_SIZE)
        
        # --- Initialize Feature Extractor ---
        self.pe_extractor = PEFeatureExtractor()

        # --- Build UI ---
        self._build_ui()
        self.apply_theme()
        self.load_excluded_rules()

        # --- Initial Load ---
        if self.file_a_path and os.path.exists(self.file_a_path):
            self.load_file('A', self.file_a_path, silent=True)
        if self.file_b_path and os.path.exists(self.file_b_path):
            self.load_file('B', self.file_b_path, silent=True)
        if self.yara_path and os.path.exists(self.yara_path):
            self.load_yara_file(self.yara_path, silent=True)

    def closeEvent(self, event):
        """Save settings on exit."""
        self.save_settings()
        super().closeEvent(event)

    # --- UI Building ---
    def _build_ui(self):
        """Construct the entire user interface."""
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)
        self.outer_layout = QtWidgets.QVBoxLayout(self.central_widget)

        self._create_toolbar()
        self._create_main_layout()
        self._create_status_bar()

    def _create_toolbar(self):
        """Create the top toolbar with file operations and controls."""
        toolbar = QtWidgets.QHBoxLayout()
        
        btn_load_a = QtWidgets.QPushButton(self.style().standardIcon(QtWidgets.QStyle.SP_FileIcon), " Load File A")
        btn_load_a.clicked.connect(lambda: self.select_and_load_file('A'))
        toolbar.addWidget(btn_load_a)

        btn_load_b = QtWidgets.QPushButton(self.style().standardIcon(QtWidgets.QStyle.SP_FileIcon), " Load File B")
        btn_load_b.clicked.connect(lambda: self.select_and_load_file('B'))
        toolbar.addWidget(btn_load_b)

        btn_load_yara = QtWidgets.QPushButton("Load YARA")
        btn_load_yara.clicked.connect(self.select_and_load_yara)
        toolbar.addWidget(btn_load_yara)
        
        toolbar.addSpacing(20)

        # Analysis Toolbar
        analysis_group = QtWidgets.QGroupBox("Analysis")
        analysis_layout = QtWidgets.QHBoxLayout(analysis_group)
        
        btn_scan_yara = QtWidgets.QPushButton("Scan YARA")
        btn_scan_yara.clicked.connect(self.scan_yara_only)
        analysis_layout.addWidget(btn_scan_yara)

        btn_scan_diff = QtWidgets.QPushButton("Scan YARA + Diff")
        btn_scan_diff.clicked.connect(self.scan_yara_and_diff)
        analysis_layout.addWidget(btn_scan_diff)
        
        btn_pe_features = QtWidgets.QPushButton("Extract PE Features")
        btn_pe_features.clicked.connect(self.run_pe_feature_extraction)
        analysis_layout.addWidget(btn_pe_features)
        
        btn_detectiteasy = QtWidgets.QPushButton("Run DetectItEasy")
        btn_detectiteasy.clicked.connect(self.run_detectiteasy_scan)
        analysis_layout.addWidget(btn_detectiteasy)

        toolbar.addWidget(analysis_group)

        btn_clear = QtWidgets.QPushButton(self.style().standardIcon(QtWidgets.QStyle.SP_DialogResetButton), " Clear All")
        btn_clear.clicked.connect(self.clear_all)
        toolbar.addWidget(btn_clear)

        toolbar.addStretch()

        self.theme_toggle_button = QtWidgets.QPushButton("Toggle Dark/Light Theme")
        self.theme_toggle_button.setCheckable(True)
        self.theme_toggle_button.setChecked(self.is_dark_theme)
        self.theme_toggle_button.clicked.connect(self.toggle_theme)
        toolbar.addWidget(self.theme_toggle_button)

        self.outer_layout.addLayout(toolbar)

    def _create_main_layout(self):
        """Create the main splitter layout with left and right panes."""
        main_split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.outer_layout.addWidget(main_split, stretch=1)

        # --- Left Pane (Lists and Editors) ---
        left_pane = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_pane)
        main_split.addWidget(left_pane)
        left_pane.setMinimumWidth(450)

        self.main_tabs = QtWidgets.QTabWidget()
        left_layout.addWidget(self.main_tabs, stretch=1)

        # --- Results Tab ---
        results_widget = QtWidgets.QWidget()
        results_layout = QtWidgets.QVBoxLayout(results_widget)
        self.main_tabs.addTab(results_widget, "Scan Results")

        self.hunk_list = QtWidgets.QListWidget()
        self.hunk_list.itemSelectionChanged.connect(self.on_select_hunk)
        results_layout.addWidget(QtWidgets.QLabel("<b>Diff Hunks</b>"))
        results_layout.addWidget(self.hunk_list)

        self.yara_list = QtWidgets.QListWidget()
        self.yara_list.itemSelectionChanged.connect(self.on_select_yara)
        results_layout.addWidget(QtWidgets.QLabel("<b>YARA Matches</b>"))
        results_layout.addWidget(self.yara_list)

        self.capa_list = QtWidgets.QListWidget()
        self.capa_list.itemSelectionChanged.connect(self.on_select_capa_match)
        results_layout.addWidget(QtWidgets.QLabel("<b>CAPA Matches</b>"))
        results_layout.addWidget(self.capa_list)

        # --- PE Analysis Tab ---
        self._create_pe_analysis_tab(self.main_tabs)

        # --- DetectItEasy Tab ---
        self.die_output = QtWidgets.QPlainTextEdit()
        self.die_output.setReadOnly(True)
        self.die_output.setFont(QtGui.QFont("Consolas", 10))
        self.main_tabs.addTab(self.die_output, "DetectItEasy")
        
        # --- Editors Tab ---
        editors_widget = QtWidgets.QWidget()
        editors_layout = QtWidgets.QVBoxLayout(editors_widget)
        self.main_tabs.addTab(editors_widget, "Editors")
        
        editor_tabs = QtWidgets.QTabWidget()
        editors_layout.addWidget(editor_tabs)

        yara_editor_widget = self._create_editor_tab("YARA Editor", self.save_yara_from_editor, self.validate_yara_editor)
        self.yara_editor = yara_editor_widget.findChild(QtWidgets.QTextEdit)
        self.yara_highlighter = YaraHighlighter(self.yara_editor.document())
        editor_tabs.addTab(yara_editor_widget, "YARA Editor")
        
        capa_editor_widget = self._create_editor_tab("CAPA Editor")
        self.capa_editor = capa_editor_widget.findChild(QtWidgets.QTextEdit)
        self.capa_highlighter = CapaHighlighter(self.capa_editor.document())
        editor_tabs.addTab(capa_editor_widget, "CAPA Editor")

        # --- yarGen GUI Tab ---
        self._create_yargen_gui_tab(self.main_tabs)

        # --- ClamAV SigTool Tab ---
        self._create_clamav_gui_tab(self.main_tabs)
        
        # --- Excluded Rules Tab ---
        self._create_excluded_rules_tab(self.main_tabs)

        left_layout.addWidget(QtWidgets.QLabel("<b>Selection Details</b>"))
        self.details = QtWidgets.QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(160)
        left_layout.addWidget(self.details)

        # --- Right Pane (Hex and Asm) ---
        right_pane = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_pane)
        main_split.addWidget(right_pane)

        self._create_hex_view(right_layout)
        self._create_asm_view(right_layout)
        
        main_split.setSizes([500, 1100])

    def _create_pe_analysis_tab(self, parent_tabs):
        """Creates the tab for PE feature extraction and resource viewing."""
        pe_widget = QtWidgets.QWidget()
        pe_layout = QtWidgets.QVBoxLayout(pe_widget)
        parent_tabs.addTab(pe_widget, "PE Analysis")

        # Toolbar for this tab
        pe_toolbar = QtWidgets.QHBoxLayout()
        self.pe_file_selector = QtWidgets.QComboBox()
        self.pe_file_selector.addItems(["File A", "File B"])
        pe_toolbar.addWidget(QtWidgets.QLabel("Target:"))
        pe_toolbar.addWidget(self.pe_file_selector)
        
        self.btn_generate_yara = QtWidgets.QPushButton("Generate Rule with yarGen")
        self.btn_generate_yara.clicked.connect(self.prepare_yargen_for_current_file)
        self.btn_generate_yara.setEnabled(False)
        pe_toolbar.addWidget(self.btn_generate_yara)
        pe_toolbar.addStretch()
        pe_layout.addLayout(pe_toolbar)

        # Tab widget for features and resources
        pe_analysis_tabs = QtWidgets.QTabWidget()
        pe_layout.addWidget(pe_analysis_tabs)

        # Features view
        self.pe_features_output = QtWidgets.QTextEdit()
        self.pe_features_output.setReadOnly(True)
        self.pe_features_output.setFont(QtGui.QFont("Consolas", 10))
        pe_analysis_tabs.addTab(self.pe_features_output, "Extracted Features")

        # Resource viewer
        self.resource_tree = QtWidgets.QTreeWidget()
        self.resource_tree.setHeaderLabels(["Type", "ID/Name", "Language", "Size", "Offset"])
        self.resource_tree.setColumnWidth(0, 150)
        pe_analysis_tabs.addTab(self.resource_tree, "Resource Viewer")

    def _create_editor_tab(self, title, save_func=None, validate_func=None):
        """Helper to create a generic editor tab with optional buttons."""
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)
        layout.setContentsMargins(0, 5, 0, 0)

        toolbar = QtWidgets.QHBoxLayout()
        if save_func:
            btn_save = QtWidgets.QPushButton("Save")
            btn_save.clicked.connect(save_func)
            toolbar.addWidget(btn_save)
        if validate_func:
            btn_validate = QtWidgets.QPushButton("Validate")
            btn_validate.clicked.connect(validate_func)
            toolbar.addWidget(btn_validate)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        editor = QtWidgets.QTextEdit()
        font = QtGui.QFont("Consolas" if sys.platform == "win32" else "Monaco", 11)
        editor.setFont(font)
        layout.addWidget(editor)
        
        return widget

    def _create_yargen_gui_tab(self, tabs):
        """Create the yarGen GUI tab with all its controls."""
        self.yargen_widget = QtWidgets.QWidget()
        yargen_layout = QtWidgets.QVBoxLayout(self.yargen_widget)
        
        form_layout = QtWidgets.QFormLayout()
        
        self.yargen_malware_path = QtWidgets.QLineEdit()
        self.yargen_output_file = QtWidgets.QLineEdit()
        self.yargen_author = QtWidgets.QLineEdit("Emirhan Ucan & Hacimurad")
        self.yargen_reference = QtWidgets.QLineEdit("VirusShare, VirusSign, ClamAV, Dr.Web, Emsisoft, Avast, VirusTotal")
        
        form_layout.addRow("Malware Path (-m):", self.yargen_malware_path)
        form_layout.addRow("Output File (-o):", self.yargen_output_file)
        form_layout.addRow("Author (-a):", self.yargen_author)
        form_layout.addRow("Reference (-r):", self.yargen_reference)
        
        yargen_layout.addLayout(form_layout)
        
        flags_layout = QtWidgets.QHBoxLayout()
        self.yargen_opcodes = QtWidgets.QCheckBox("--opcodes")
        self.yargen_meaningful = QtWidgets.QCheckBox("--meaningful-words-only")
        self.yargen_excludegood = QtWidgets.QCheckBox("--excludegood")
        self.yargen_nofilesize = QtWidgets.QCheckBox("--nofilesize")
        self.yargen_nosimple = QtWidgets.QCheckBox("--nosimple")

        flags_layout.addWidget(self.yargen_opcodes)
        flags_layout.addWidget(self.yargen_meaningful)
        flags_layout.addWidget(self.yargen_excludegood)
        flags_layout.addWidget(self.yargen_nofilesize)
        flags_layout.addWidget(self.yargen_nosimple)
        yargen_layout.addLayout(flags_layout)

        btn_layout = QtWidgets.QHBoxLayout()
        btn_run_yargen = QtWidgets.QPushButton("Run yarGen")
        btn_run_yargen.clicked.connect(self.run_yargen_from_gui)
        btn_update_yargen = QtWidgets.QPushButton("Update yarGen DB")
        btn_update_yargen.clicked.connect(self.update_yargen_db)
        btn_layout.addWidget(btn_run_yargen)
        btn_layout.addWidget(btn_update_yargen)
        yargen_layout.addLayout(btn_layout)
        
        self.yargen_console = QtWidgets.QPlainTextEdit()
        self.yargen_console.setReadOnly(True)
        yargen_layout.addWidget(self.yargen_console)
        
        tabs.addTab(self.yargen_widget, "yarGen GUI")

    def _create_clamav_gui_tab(self, tabs):
        """Create the ClamAV SigTool GUI tab."""
        self.clamav_widget = QtWidgets.QWidget()
        clamav_layout = QtWidgets.QVBoxLayout(self.clamav_widget)
        
        # --- Database Inspector ---
        db_inspector_group = QtWidgets.QGroupBox("Database Inspector")
        db_inspector_layout = QtWidgets.QVBoxLayout(db_inspector_group)

        path_layout = QtWidgets.QHBoxLayout()
        self.clamav_db_path = QtWidgets.QLineEdit()
        self.clamav_db_path.setPlaceholderText("Path to ClamAV database file (.cvd, .cld, etc.)")
        path_layout.addWidget(self.clamav_db_path)
        btn_browse_db = QtWidgets.QPushButton("Browse...")
        btn_browse_db.clicked.connect(self.browse_for_clamav_db)
        path_layout.addWidget(btn_browse_db)
        db_inspector_layout.addLayout(path_layout)
        
        form_layout = QtWidgets.QFormLayout()
        self.clamav_command_select = QtWidgets.QComboBox()
        self.clamav_command_select.addItems([
            "Info (--info)", 
            "List Signatures (--list-sigs)", 
            "Unpack (--unpack)", 
            "Find Signatures (--find-sigs)"
        ])
        self.clamav_command_select.currentTextChanged.connect(self.on_clamav_command_change)
        form_layout.addRow("Command:", self.clamav_command_select)
        
        self.clamav_command_arg_label = QtWidgets.QLabel("Argument:")
        self.clamav_command_arg = QtWidgets.QLineEdit()
        self.clamav_command_arg.setPlaceholderText("Regex for finding signatures")
        form_layout.addRow(self.clamav_command_arg_label, self.clamav_command_arg)
        self.clamav_command_arg_label.hide()
        self.clamav_command_arg.hide()

        db_inspector_layout.addLayout(form_layout)
        
        btn_run_sigtool = QtWidgets.QPushButton("Run DB Command")
        btn_run_sigtool.clicked.connect(self.run_sigtool_from_gui)
        db_inspector_layout.addWidget(btn_run_sigtool)
        clamav_layout.addWidget(db_inspector_group)

        # --- Signature Decoder ---
        decoder_group = QtWidgets.QGroupBox("Signature Decoder")
        decoder_layout = QtWidgets.QVBoxLayout(decoder_group)
        
        decoder_layout.addWidget(QtWidgets.QLabel("Paste Signature(s) Here:"))
        self.clamav_sig_input = QtWidgets.QTextEdit()
        self.clamav_sig_input.setPlaceholderText("MalwareName:TargetType:Offset:HexSignature...")
        self.clamav_sig_input.setAcceptRichText(False)
        self.clamav_sig_input.setFont(QtGui.QFont("Consolas", 10))
        decoder_layout.addWidget(self.clamav_sig_input)
        
        btn_decode_sig = QtWidgets.QPushButton("Decode Signature(s)")
        btn_decode_sig.clicked.connect(self.run_sigtool_decode)
        decoder_layout.addWidget(btn_decode_sig)
        clamav_layout.addWidget(decoder_group)

        # --- Console Output ---
        clamav_layout.addWidget(QtWidgets.QLabel("<b>SigTool Output</b>"))
        self.clamav_console = QtWidgets.QPlainTextEdit()
        self.clamav_console.setReadOnly(True)
        self.clamav_console.setFont(QtGui.QFont("Consolas", 10))
        clamav_layout.addWidget(self.clamav_console)
        
        tabs.addTab(self.clamav_widget, "ClamAV SigTool")

    def _create_excluded_rules_tab(self, tabs):
        """Create the tab for managing excluded YARA rules."""
        self.excluded_rules_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(self.excluded_rules_widget)

        layout.addWidget(QtWidgets.QLabel("<b>Excluded YARA Rules</b>"))
        self.excluded_rules_list = QtWidgets.QListWidget()
        layout.addWidget(self.excluded_rules_list)

        btn_layout = QtWidgets.QHBoxLayout()
        btn_add_excluded = QtWidgets.QPushButton("Exclude Directory")
        btn_add_excluded.clicked.connect(self.add_excluded_directory)
        btn_remove_excluded = QtWidgets.QPushButton("Remove Selected")
        btn_remove_excluded.clicked.connect(self.remove_selected_excluded)
        btn_layout.addWidget(btn_add_excluded)
        btn_layout.addWidget(btn_remove_excluded)
        layout.addLayout(btn_layout)

        tabs.addTab(self.excluded_rules_widget, "Excluded Rules")
        
    def _create_hex_view(self, parent_layout):
        """Create the hex view panes and controls."""
        hex_controls = QtWidgets.QHBoxLayout()
        hex_controls.addWidget(QtWidgets.QLabel("Context:"))
        self.spin_context = QtWidgets.QSpinBox()
        self.spin_context.setRange(MIN_CONTEXT_SIZE, MAX_CONTEXT_SIZE)
        self.spin_context.setValue(self.context)
        self.spin_context.valueChanged.connect(self.on_context_change)
        hex_controls.addWidget(self.spin_context)
        hex_controls.addStretch()
        parent_layout.addLayout(hex_controls)

        hex_split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        
        self.hex_a = QtWidgets.QTextEdit()
        self.hex_b = QtWidgets.QTextEdit()
        for he in (self.hex_a, self.hex_b):
            he.setReadOnly(True)
            he.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
            f = QtGui.QFont("Consolas" if sys.platform == "win32" else "DejaVu Sans Mono", 11)
            he.setFont(f)
            he.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
            he.customContextMenuRequested.connect(self.on_hex_context_menu)
        
        hex_split.addWidget(self._create_view_pane("File A Hex", self.hex_a))
        hex_split.addWidget(self._create_view_pane("File B Hex", self.hex_b))
        parent_layout.addWidget(hex_split, stretch=1)

        edit_row = QtWidgets.QHBoxLayout()
        edit_row.addWidget(QtWidgets.QLabel("Edit @ Offset (hex):"))
        self.edit_offset = QtWidgets.QLineEdit()
        self.edit_offset.setFixedWidth(120)
        self.edit_offset.setPlaceholderText("0x1234")
        edit_row.addWidget(self.edit_offset)
        edit_row.addWidget(QtWidgets.QLabel("Bytes (hex):"))
        self.edit_bytes = QtWidgets.QLineEdit()
        self.edit_bytes.setPlaceholderText("74 or 74 75 90")
        edit_row.addWidget(self.edit_bytes)
        btn_apply_edit = QtWidgets.QPushButton("Apply Edit")
        btn_apply_edit.clicked.connect(self.apply_edit_from_controls)
        edit_row.addWidget(btn_apply_edit)
        parent_layout.addLayout(edit_row)

    def _create_asm_view(self, parent_layout):
        """Create the disassembly view panes."""
        asm_split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        
        self.asm_a = QtWidgets.QPlainTextEdit()
        self.asm_b = QtWidgets.QPlainTextEdit()
        for a in (self.asm_a, self.asm_b):
            a.setReadOnly(True)
            fa = QtGui.QFont("Consolas" if sys.platform == "win32" else "DejaVu Sans Mono", 10)
            a.setFont(fa)
        
        asm_split.addWidget(self._create_view_pane("File A Assembly", self.asm_a))
        asm_split.addWidget(self._create_view_pane("File B Assembly", self.asm_b))
        parent_layout.addWidget(asm_split, stretch=1)

    def _create_view_pane(self, title, widget):
        """Helper to create a titled pane for a view widget."""
        pane = QtWidgets.QGroupBox(title)
        layout = QtWidgets.QVBoxLayout(pane)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.addWidget(widget)
        return pane

    def _create_status_bar(self):
        """Create the bottom status bar."""
        self.status_bar = self.statusBar()
        self.lbl_status = QtWidgets.QLabel("Ready")
        self.status_bar.addWidget(self.lbl_status)
        
        capa_widget = QtWidgets.QWidget()
        capa_layout = QtWidgets.QHBoxLayout(capa_widget)
        capa_layout.setContentsMargins(0, 0, 0, 0)
        capa_layout.addWidget(QtWidgets.QLabel("CAPA Path:"))
        self.capa_path_edit = QtWidgets.QLineEdit("capa.exe")
        self.capa_path_edit.setFixedWidth(150)
        capa_layout.addWidget(self.capa_path_edit)
        
        btn_run_capa_a = QtWidgets.QPushButton("Run CAPA on A")
        btn_run_capa_a.clicked.connect(lambda: self.run_capa_on('A'))
        capa_layout.addWidget(btn_run_capa_a)
        
        btn_run_capa_b = QtWidgets.QPushButton("Run CAPA on B")
        btn_run_capa_b.clicked.connect(lambda: self.run_capa_on('B'))
        capa_layout.addWidget(btn_run_capa_b)
        
        self.status_bar.addPermanentWidget(capa_widget)

    # --- Theming ---
    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        self.theme_toggle_button.setChecked(self.is_dark_theme)
        self.apply_theme()

    def apply_theme(self):
        if self.is_dark_theme:
            self.setStyleSheet(self.get_dark_theme_style())
        else:
            self.setStyleSheet(self.get_light_theme_style())
        self._refresh_all_views() 

    def get_light_theme_style(self):
            return """
                QMainWindow, QWidget { 
                    background-color: #F0F0F0; 
                    color: #000000; /* Sets default text color to black */
                }
                QTextEdit, QPlainTextEdit, QTreeWidget { 
                    background-color: #FFFFFF; 
                    color: #000000; 
                    border: 1px solid #CCCCCC; 
                }
                QListWidget { 
                    background-color: #FFFFFF; 
                    color: #000000; 
                    border: 1px solid #CCCCCC; 
                }
                QPushButton { 
                    background-color: #E1E1E1; 
                    color: #000000; /* Explicitly set button text color */
                    border: 1px solid #ADADAD; 
                    padding: 5px; 
                    border-radius: 2px; 
                }
                QPushButton:hover { 
                    background-color: #E5F1FB; 
                    border: 1px solid #0078D7; 
                }
                QPushButton:pressed { 
                    background-color: #CCE4F7; 
                }
                QLabel, QGroupBox { 
                    color: #000000; 
                }
                QGroupBox { 
                    border: 1px solid #CCCCCC; 
                    margin-top: 0.5em; 
                }
                QGroupBox::title { 
                    subcontrol-origin: margin; 
                    left: 10px; 
                    padding: 0 3px 0 3px; 
                }
                QLineEdit, QSpinBox, QComboBox { 
                    background-color: #FFFFFF; 
                    color: #000000; 
                    border: 1px solid #ADADAD; 
                    padding: 2px; 
                }
                QTabWidget::pane { 
                    border: 1px solid #CCCCCC; 
                }
                QTabBar::tab { 
                    background: #E1E1E1; 
                    color: #000000; /* Explicitly set tab text color */
                    padding: 8px; 
                }
                QTabBar::tab:selected { 
                    background: #FFFFFF; 
                }
                QSplitter::handle { 
                    background: #CCCCCC; 
                }
            """

    def get_dark_theme_style(self):
        return """
            QMainWindow, QWidget { background-color: #2D2D30; color: #F1F1F1; }
            QTextEdit, QPlainTextEdit, QTreeWidget { background-color: #1E1E1E; color: #D4D4D4; border: 1px solid #3E3E42; }
            QListWidget { background-color: #252526; color: #CCCCCC; border: 1px solid #3E3E42; }
            QPushButton { background-color: #3E3E42; border: 1px solid #555555; padding: 5px; border-radius: 2px; }
            QPushButton:hover { background-color: #4F4F53; }
            QPushButton:pressed { background-color: #007ACC; }
            QLabel, QGroupBox { color: #F1F1F1; }
            QGroupBox { border: 1px solid #3E3E42; margin-top: 0.5em; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px 0 3px; }
            QLineEdit, QSpinBox, QComboBox { background-color: #3C3C3C; color: #F1F1F1; border: 1px solid #555555; padding: 2px; }
            QTabWidget::pane { border: 1px solid #3E3E42; }
            QTabBar::tab { background: #2D2D30; padding: 8px; border: 1px solid #3E3E42; }
            QTabBar::tab:selected { background: #1E1E1E; }
            QSplitter::handle { background: #3E3E42; }
        """

    # --- Settings Management ---
    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r') as f:
                    return json.load(f)
            except (IOError, json.JSONDecodeError) as e:
                logging.warning(f"Could not load settings: {e}")
        return {}

    def save_settings(self):
        settings = {
            "dark_theme": self.is_dark_theme,
            "file_a_path": self.file_a_path,
            "file_b_path": self.file_b_path,
            "yara_path": self.yara_path,
            "context": self.context,
            "excluded_rules_dirs": [self.excluded_rules_list.item(i).text() for i in range(self.excluded_rules_list.count())]
        }
        try:
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(settings, f, indent=4)
        except IOError as e:
            logging.error(f"Could not save settings: {e}")

    # --- File Operations ---
    def select_and_load_file(self, which: str):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, f"Load File {which}")
        if path:
            self.load_file(which, path)

    def load_file(self, which: str, path: str, silent: bool = False):
        try:
            with open(path, "rb") as f:
                data = f.read()
            
            if which == 'A':
                self.file_a_path = path
                self.file_a_data = bytearray(data)
                self.pe_features_a = None
            else:
                self.file_b_path = path
                self.file_b_data = bytearray(data)
                self.pe_features_b = None
            
            self.lbl_status.setText(f"Loaded {which}: {os.path.basename(path)} ({len(data)} bytes)")
            self._refresh_all_views()

        except Exception as e:
            msg = f"Error loading File {which}: {e}"
            logging.error(msg)
            if not silent:
                QtWidgets.QMessageBox.critical(self, f"Load Error", msg)
    
    def select_and_load_yara(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Load YARA Rules", filter="YARA files (*.yar *.yara);;All files (*)")
        if path:
            self.load_yara_file(path)

    def load_yara_file(self, path: str, silent: bool = False):
        self.yara_path = path
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
            self.yara_editor.setPlainText(txt)
            self.lbl_status.setText(f"Loaded YARA: {os.path.basename(path)}")
        except Exception as e:
            msg = f"YARA load error: {e}"
            logging.error(msg)
            if not silent:
                QtWidgets.QMessageBox.critical(self, "YARA Load Error", msg)

    def save_yara_from_editor(self):
        path = self.yara_path
        if not path:
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save YARA Rules", filter="YARA files (*.yar *.yara)")
            if not path:
                return
            self.yara_path = path
        
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.yara_editor.toPlainText())
            self.lbl_status.setText(f"YARA saved to {os.path.basename(path)}")
            QtWidgets.QMessageBox.information(self, "Saved", f"YARA rules saved to {path}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Save Error", str(e))

    def validate_yara_editor(self):
        if not YARA_AVAILABLE:
            QtWidgets.QMessageBox.warning(self, "YARA-X Missing", "yara-x is not installed. Please run: pip install yara-x")
            return
        
        try:
            rules_text = self.yara_editor.toPlainText()
            if not rules_text.strip():
                QtWidgets.QMessageBox.information(self, "YARA Valid", "Editor is empty, but no syntax errors.")
                return

            yara_x.compile(rules_text)
            QtWidgets.QMessageBox.information(self, "YARA Valid", "The current YARA rules compiled successfully.")
        except yara_x.CompileError as e:
            # yara-x compile errors can be quite verbose and structured. 
            # Let's format it nicely for the message box.
            error_message = f"YARA Compile Error:\n\n{e}"
            QtWidgets.QMessageBox.critical(self, "YARA Compile Error", error_message)
        except Exception as e:
            # Catch any other unexpected errors
            QtWidgets.QMessageBox.critical(self, "Validation Error", f"An unexpected error occurred: {e}")

    def run_yargen_from_gui(self):
        yar_gen_path = os.path.join(script_dir, "yarGen.py")
        if not os.path.exists(yar_gen_path):
            QtWidgets.QMessageBox.warning(self, "yarGen Not Found", "Could not find yarGen.py in the script directory.")
            return

        command = [sys.executable, yar_gen_path]
        
        malware_path = self.yargen_malware_path.text()
        if not malware_path:
            QtWidgets.QMessageBox.warning(self, "Input Missing", "Please provide a malware path.")
            return
        command.extend(["-m", malware_path])
        
        output_file = self.yargen_output_file.text()
        if output_file:
            command.extend(["-o", output_file])
            
        author = self.yargen_author.text()
        if author:
            command.extend(["-a", author])
            
        reference = self.yargen_reference.text()
        if reference:
            command.extend(["-r", reference])

        if self.yargen_opcodes.isChecked(): command.append("--opcodes")
        if self.yargen_meaningful.isChecked(): command.append("--meaningful-words-only")
        if self.yargen_excludegood.isChecked(): command.append("--excludegood")
        if self.yargen_nofilesize.isChecked(): command.append("--nofilesize")
        if self.yargen_nosimple.isChecked(): command.append("--nosimple")

        self.run_generic_subprocess(command, self.yargen_console)

    def update_yargen_db(self):
        yar_gen_path = os.path.join(script_dir, "yarGen.py")
        if not os.path.exists(yar_gen_path):
            QtWidgets.QMessageBox.warning(self, "yarGen Not Found", "Could not find yarGen.py in the script directory.")
            return
        command = [sys.executable, yar_gen_path, "--update"]
        self.run_generic_subprocess(command, self.yargen_console)

    def run_generic_subprocess(self, command, output_widget, stdin_data=None):
        output_widget.clear()
        self.lbl_status.setText(f"Running: {' '.join(command)}")

        def bg_task():
            try:
                startupinfo = None
                if os.name == 'nt':
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

                process = subprocess.Popen(
                    command, 
                    stdin=subprocess.PIPE if stdin_data else None,
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.STDOUT, 
                    text=True, 
                    encoding='utf-8', 
                    errors='ignore',
                    startupinfo=startupinfo
                )
                
                if stdin_data:
                    stdout_data, _ = process.communicate(input=stdin_data)
                    QtCore.QMetaObject.invokeMethod(output_widget, "setPlainText", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, stdout_data.strip()))
                else:
                    while True:
                        output = process.stdout.readline()
                        if output == '' and process.poll() is not None:
                            break
                        if output:
                            QtCore.QMetaObject.invokeMethod(output_widget, "appendPlainText", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, output.strip()))
                
                return_code = process.poll()
                if return_code == 0:
                    self.lbl_status.setText("Command finished successfully.")
                else:
                    self.lbl_status.setText(f"Command failed with exit code {return_code}.")

            except Exception as e:
                self.lbl_status.setText(f"Error executing command: {e}")

        threading.Thread(target=bg_task, daemon=True).start()


    # --- Analysis and Scanning ---
    def scan_yara_only(self):
        if not self.yara_path:
            QtWidgets.QMessageBox.warning(self, "No YARA", "Load a YARA rule file first.")
            return
        self.lbl_status.setText("Scanning with YARA...")
        
        def bg_task():
            try:
                self.matches_a = collect_yara_matches(self.yara_path, bytes(self.file_a_data), self.excluded_rules) if self.file_a_data else []
                self.matches_b = collect_yara_matches(self.yara_path, bytes(self.file_b_data), self.excluded_rules) if self.file_b_data else []
                self.diff_hunks = []
                self._build_yara_index()
                QtCore.QMetaObject.invokeMethod(self, "_refresh_lists_and_views", QtCore.Qt.QueuedConnection)
                self.lbl_status.setText("YARA scan complete.")
            except Exception as e:
                QtCore.QMetaObject.invokeMethod(self.lbl_status, "setText", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, f"YARA Error: {e}"))

        threading.Thread(target=bg_task, daemon=True).start()

    def scan_yara_and_diff(self):
        if self.file_a_data is None or self.file_b_data is None:
            QtWidgets.QMessageBox.warning(self, "Missing Files", "Load both File A and File B to run a diff.")
            return
        self.lbl_status.setText("Scanning YARA and computing diffs...")

        def bg_task():
            try:
                self.matches_a = collect_yara_matches(self.yara_path, bytes(self.file_a_data), self.excluded_rules) if self.yara_path else []
                self.matches_b = collect_yara_matches(self.yara_path, bytes(self.file_b_data), self.excluded_rules) if self.yara_path else []
                self.diff_hunks = compute_diff_hunks(bytes(self.file_a_data), bytes(self.file_b_data))
                self._build_yara_index()
                QtCore.QMetaObject.invokeMethod(self, "_refresh_lists_and_views", QtCore.Qt.QueuedConnection)
                self.lbl_status.setText("Scan and diff complete.")
            except Exception as e:
                 QtCore.QMetaObject.invokeMethod(self.lbl_status, "setText", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, f"Scan/Diff Error: {e}"))

        threading.Thread(target=bg_task, daemon=True).start()

    def _build_yara_index(self):
        """Group YARA matches by rule and identifier."""
        idx = {}
        all_matches = self.matches_a + self.matches_b
        is_a_map = {id(m): True for m in self.matches_a}

        for m in all_matches:
            key = (m['rule_name'], m['identifier'])
            if key not in idx:
                idx[key] = {'a_offsets': [], 'b_offsets': []}
            
            if is_a_map.get(id(m), False):
                idx[key]['a_offsets'].append(m['offset'])
            else:
                idx[key]['b_offsets'].append(m['offset'])
        
        self.yara_index = idx

    @QtCore.Slot()
    def _refresh_lists_and_views(self):
        """Update the UI lists (hunks, YARA matches) and refresh views."""
        self.hunk_list.clear()
        for i, h in enumerate(self.diff_hunks):
            off, ln = h['start'], h['length']
            pa = binascii.hexlify(self.file_a_data[off:off+8]).decode().upper() if self.file_a_data and off < len(self.file_a_data) else ""
            pb = binascii.hexlify(self.file_b_data[off:off+8]).decode().upper() if self.file_b_data and off < len(self.file_b_data) else ""
            self.hunk_list.addItem(f"#{i+1}: 0x{off:08X} [+{ln}]  A:{pa} B:{pb}")

        self.yara_list.clear()
        self._yara_keys = sorted(self.yara_index.keys(), key=lambda k: (k[0], str(k[1])))
        for key in self._yara_keys:
            val = self.yara_index[key]
            rule, ident = key
            a_cnt, b_cnt = len(val['a_offsets']), len(val['b_offsets'])
            tag = " (A&B)" if a_cnt and b_cnt else (" (A)" if a_cnt else " (B)")
            self.yara_list.addItem(f"{rule}::{ident}{tag}  [A:{a_cnt}, B:{b_cnt}]")
        
        self.capa_list.clear()
        for which, match in self.capa_matches:
            addr = match['address']
            cap = match['capability']
            self.capa_list.addItem(f"[{which}] 0x{addr:08X}: {cap}")

        self._refresh_all_views()

    # --- Rendering and Views ---
    def _refresh_all_views(self):
        """Re-render all data views (hex, asm) based on current state."""
        center = 0
        if self.matches_a:
            center = self.matches_a[0]['offset']
        elif self.matches_b:
            center = self.matches_b[0]['offset']
        self.render_region(center=center)

    def render_region(self, center=0, yara_key=None):
        """Render a specific region of the files centered around an offset."""
        ctx = self.context
        start = max(0, center - ctx)
        
        self.render_hex_panes(start, yara_key)
        self._disassemble_region(center)

    def render_hex_panes(self, start_addr, yara_key=None):
        """Render both hex panes."""
        self.hex_a.setHtml(self._render_hex_html(True, start_addr, yara_key))
        self.hex_b.setHtml(self._render_hex_html(False, start_addr, yara_key))

    def _render_hex_html(self, is_left: bool, start: int, yara_key=None) -> str:
        """Generates the HTML for a single hex pane."""
        data = self.file_a_data if is_left else self.file_b_data
        other_data = self.file_b_data if is_left else self.file_a_data
        matches = self.matches_a if is_left else self.matches_b
        
        if data is None:
            return ""

        yara_intervals = intervals_from_matches(matches)
        
        selected_yara_intervals = []
        if yara_key:
            for m in matches:
                if (m['rule_name'], m['identifier']) == yara_key:
                    offset = m.get("offset", 0)
                    length = m.get("length", 0)
                    selected_yara_intervals.append((offset, offset + length - 1))

        bg_color = "#1E1E1E" if self.is_dark_theme else "#FFFFFF"
        text_color = "#D4D4D4" if self.is_dark_theme else "#000000"
        addr_color = "#6E6E6E" if self.is_dark_theme else "#888888"
        diff_bg = "#5A3800" if self.is_dark_theme else "#FFF2B2"
        yar_bg = "#8B0000" if self.is_dark_theme else "#F26B6B"
        yar_sel_bg = "#B22222" if self.is_dark_theme else "#B23B3B"

        css = f"""
        <style>
            body {{ background-color: {bg_color}; color: {text_color}; font-family: Consolas, 'DejaVu Sans Mono', monospace; font-size: 11px; }}
            .addr {{ color: {addr_color}; }}
            .diff {{ background-color: {diff_bg}; }}
            .yar {{ background-color: {yar_bg}; color: white; }}
            .yarsel {{ background-color: {yar_sel_bg}; color: white; font-weight: bold;}}
        </style>
        """
        
        html = ["<html><head>", css, "</head><body><pre>"]
        
        end = min(start + self.context * 2, len(data))
        pos = start - (start % BYTES_PER_ROW)

        while pos < end:
            addr = f"<span class='addr'>0x{pos:08X}:</span> "
            hex_parts = []
            ascii_parts = []

            for j in range(BYTES_PER_ROW):
                offset = pos + j
                if offset < len(data):
                    byte_val = data[offset]
                    char = chr(byte_val) if 32 <= byte_val <= 126 else '.'
                    
                    classes = []
                    if self.show_diff and other_data and (offset >= len(other_data) or other_data[offset] != byte_val):
                        classes.append("diff")
                    if interval_contains(selected_yara_intervals, offset):
                        classes.append("yarsel")
                    elif interval_contains(yara_intervals, offset):
                        classes.append("yar")
                    
                    class_attr = f' class="{" ".join(classes)}"' if classes else ""
                    hex_parts.append(f"<span{class_attr}>{byte_val:02X}</span>")
                    ascii_parts.append(f"<span{class_attr}>{char.replace('&', '&amp;').replace('<', '&lt;')}</span>")
                else:
                    hex_parts.append("  ")
                    ascii_parts.append(" ")

            hex_str = " ".join(hex_parts)
            ascii_str = "".join(ascii_parts)
            html.append(f"{addr}{hex_str}  |{ascii_str}|")
            pos += BYTES_PER_ROW

        html.extend(["</pre></body></html>"])
        return "\n".join(html)

    def _disassemble_region(self, center: int):
        if not CAPSTONE_AVAILABLE:
            self.asm_a.setPlainText("Capstone library not found. Please install it.")
            self.asm_b.setPlainText("pip install capstone")
            return

        size = 256
        start = max(0, center - size // 2)
        
        try:
            cs = Cs(CS_ARCH_X86, CS_MODE_64)
            cs.detail = True
        except Exception as e:
            self.asm_a.setPlainText(f"Capstone init error: {e}")
            self.asm_b.setPlainText("")
            return

        def disasm_into(pane, data, base_addr):
            if not data:
                pane.setPlainText("(no data)")
                return
            
            out = []
            try:
                for insn in cs.disasm(bytes(data), base_addr):
                    bh = binascii.hexlify(insn.bytes).decode().upper()
                    out.append(f"0x{insn.address:08X}: {bh:<20} {insn.mnemonic} {insn.op_str}")
                pane.setPlainText("\n".join(out))
            except Exception as e:
                pane.setPlainText(f"Disassembly error: {e}")

        data_a = self.file_a_data[start : start + size] if self.file_a_data else b""
        data_b = self.file_b_data[start : start + size] if self.file_b_data else b""
        disasm_into(self.asm_a, data_a, start)
        disasm_into(self.asm_b, data_b, start)

    # --- Event Handlers and Slots ---
    def on_context_change(self, value):
        self.context = value
        self._refresh_all_views()

    def on_select_hunk(self):
        sel_idx = self.hunk_list.currentRow()
        if 0 <= sel_idx < len(self.diff_hunks):
            hunk = self.diff_hunks[sel_idx]
            self._show_hunk_details(hunk)
            self.render_region(center=hunk['start'])

    def on_select_yara(self):
        sel_idx = self.yara_list.currentRow()
        if 0 <= sel_idx < len(self._yara_keys):
            key = self._yara_keys[sel_idx]
            self._show_yara_details(key)
            
            offs = self.yara_index.get(key, {})
            center = offs.get('a_offsets', [offs.get('b_offsets', [0])[0]])[0]
            self.render_region(center=center, yara_key=key)
            
    def on_select_capa_match(self):
        sel_idx = self.capa_list.currentRow()
        if 0 <= sel_idx < len(self.capa_matches):
            which, match = self.capa_matches[sel_idx]
            self.details.setPlainText(f"CAPA Match in File {which}\n"
                                      f"Capability: {match['capability']}\n"
                                      f"Address: 0x{match['address']:X}")
            self.render_region(center=match['address'])

    def on_hex_context_menu(self, pos):
        sender = self.sender()
        menu = QtWidgets.QMenu()
        menu.addAction("Copy Displayed Text", lambda: QtWidgets.QApplication.clipboard().setText(sender.toPlainText()))
        menu.addAction("Edit Bytes at Offset...", self.open_edit_dialog)
        menu.exec_(sender.mapToGlobal(pos))

    def open_edit_dialog(self):
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Edit Bytes")
        layout = QtWidgets.QFormLayout(dlg)
        
        offset_edit = QtWidgets.QLineEdit()
        offset_edit.setPlaceholderText("e.g., 0x1234 or 4660")
        bytes_edit = QtWidgets.QLineEdit()
        bytes_edit.setPlaceholderText("e.g., 90 90 or C3")
        
        layout.addRow("Offset (hex or dec):", offset_edit)
        layout.addRow("Bytes (hex):", bytes_edit)
        
        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        layout.addRow(buttons)

        if dlg.exec() == QtWidgets.QDialog.Accepted:
            try:
                off_str = offset_edit.text().strip()
                offset = int(off_str, 16) if off_str.lower().startswith("0x") else int(off_str)
                
                bts_str = bytes_edit.text().strip().replace(" ", "")
                bts = binascii.unhexlify(bts_str)
                
                which, ok = QtWidgets.QInputDialog.getItem(self, "Select Target", "Apply edit to:", ["File A", "File B"], 0, False)
                if ok:
                    self.apply_edit(which[-1], offset, bts)
            except (ValueError, binascii.Error) as e:
                QtWidgets.QMessageBox.critical(self, "Invalid Input", f"Could not apply edit: {e}")

    def apply_edit_from_controls(self):
        try:
            off_str = self.edit_offset.text().strip()
            if not off_str: return
            offset = int(off_str, 16) if off_str.lower().startswith("0x") else int(off_str)
            
            bts_str = self.edit_bytes.text().strip().replace(" ", "")
            if not bts_str: return
            bts = binascii.unhexlify(bts_str)
            
            which, ok = QtWidgets.QInputDialog.getItem(self, "Select Target", "Apply edit to:", ["File A", "File B"], 0, False)
            if ok:
                self.apply_edit(which[-1], offset, bts)
        except (ValueError, binascii.Error) as e:
            QtWidgets.QMessageBox.critical(self, "Invalid Input", f"Could not apply edit: {e}")

    def apply_edit(self, which: str, offset: int, bts: bytes):
        buf = self.file_a_data if which == 'A' else self.file_b_data
        if buf is None:
            QtWidgets.QMessageBox.warning(self, "No Data", f"File {which} is not loaded.")
            return
        
        if not (0 <= offset < len(buf)):
            QtWidgets.QMessageBox.warning(self, "Invalid Offset", "Offset is out of range.")
            return

        end = offset + len(bts)
        if end > len(buf):
            buf.extend(b'\x00' * (end - len(buf)))
        
        buf[offset:end] = bts
        self.lbl_status.setText(f"Applied {len(bts)}-byte edit to File {which} at 0x{offset:X}")
        self._refresh_all_views()

    def run_capa_on(self, which: str):
        path = self.file_a_path if which == 'A' else self.file_b_path
        if not path:
            QtWidgets.QMessageBox.warning(self, "No File", f"File {which} is not loaded.")
            return
        
        capa_exe = self.capa_path_edit.text().strip()
        self.lbl_status.setText(f"Running CAPA on File {which}...")
        
        def bg_task():
            res_path = run_capa_analysis(path, capa_exe)
            if res_path:
                try:
                    with open(res_path, 'r', encoding='utf-8') as f:
                        results = f.read()
                    
                    parsed_matches = parse_capa_output(results)
                    self.capa_matches = [m for m in self.capa_matches if m[0] != which]
                    self.capa_matches.extend([(which, match) for match in parsed_matches])
                    
                    QtCore.QMetaObject.invokeMethod(self.capa_editor, "setPlainText", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, results))
                    QtCore.QMetaObject.invokeMethod(self, "_refresh_lists_and_views", QtCore.Qt.QueuedConnection)
                    self.lbl_status.setText(f"CAPA analysis for {which} complete.")
                except Exception as e:
                    self.lbl_status.setText(f"Error reading CAPA results: {e}")
            else:
                self.lbl_status.setText(f"CAPA analysis for {which} failed.")

        threading.Thread(target=bg_task, daemon=True).start()

    def run_pe_feature_extraction(self):
        """Extracts and displays PE features for the selected file."""
        which_str, ok = QtWidgets.QInputDialog.getItem(self, "Select Target", "Extract features for:", ["File A", "File B"], 0, False)
        if not ok:
            return
        
        which = 'A' if which_str == "File A" else 'B'
        path = self.file_a_path if which == 'A' else self.file_b_path
        
        if not path:
            QtWidgets.QMessageBox.warning(self, "No File", f"File {which} is not loaded.")
            return
            
        self.lbl_status.setText(f"Extracting PE features for File {which}...")
        
        def bg_task():
            features = self.pe_extractor.extract_numeric_features(path)
            if which == 'A':
                self.pe_features_a = features
            else:
                self.pe_features_b = features
            
            QtCore.QMetaObject.invokeMethod(self, "display_pe_features", QtCore.Qt.QueuedConnection)
            self.lbl_status.setText(f"PE feature extraction for File {which} complete.")

        threading.Thread(target=bg_task, daemon=True).start()
        
    def browse_for_clamav_db(self):
        """Opens a file dialog to select a ClamAV database file."""
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select ClamAV Database", filter="ClamAV DB (*.cvd *.cld *.ndb *.hdb *.ldb);;All files (*)")
        if path:
            self.clamav_db_path.setText(path)

    def on_clamav_command_change(self, text):
        """Shows or hides the argument input based on the selected command."""
        if "--find-sigs" in text:
            self.clamav_command_arg_label.show()
            self.clamav_command_arg.show()
        else:
            self.clamav_command_arg_label.hide()
            self.clamav_command_arg.hide()

    def run_sigtool_from_gui(self):
        """Constructs and runs the sigtool command for database inspection."""
        sigtool_path = os.path.join(script_dir, "clamav", "sigtool.exe")
        if not os.path.exists(sigtool_path):
            QtWidgets.QMessageBox.warning(self, "SigTool Not Found", f"Could not find sigtool.exe at: {sigtool_path}")
            return

        db_path = self.clamav_db_path.text()
        if not db_path or not os.path.exists(db_path):
            QtWidgets.QMessageBox.warning(self, "Database File Missing", "Please provide a valid path to a ClamAV database file.")
            return

        command_str = self.clamav_command_select.currentText()
        command = [sigtool_path]

        if "--info" in command_str:
            command.extend(["--info", db_path])
        elif "--list-sigs" in command_str:
            command.extend(["--list-sigs", db_path])
        elif "--unpack" in command_str:
            command.extend(["--unpack", db_path])
        elif "--find-sigs" in command_str:
            arg = self.clamav_command_arg.text()
            if not arg:
                QtWidgets.QMessageBox.warning(self, "Argument Missing", "Please provide a regex to find signatures.")
                return
            command.extend([f"--find-sigs={arg}", db_path])
        
        self.run_generic_subprocess(command, self.clamav_console)

    def run_sigtool_decode(self):
        """Runs sigtool --decode-sigs with input from the text box."""
        sigtool_path = os.path.join(script_dir, "clamav", "sigtool.exe")
        if not os.path.exists(sigtool_path):
            QtWidgets.QMessageBox.warning(self, "SigTool Not Found", f"Could not find sigtool.exe at: {sigtool_path}")
            return

        signatures_text = self.clamav_sig_input.toPlainText()
        if not signatures_text.strip():
            QtWidgets.QMessageBox.warning(self, "Input Missing", "Please paste one or more signatures to decode.")
            return
        
        command = [sigtool_path, "--decode-sigs"]
        self.run_generic_subprocess(command, self.clamav_console, stdin_data=signatures_text)

    @QtCore.Slot()
    def display_pe_features(self):
        """Updates the PE analysis UI elements with extracted data."""
        which_str = self.pe_file_selector.currentText()
        which = 'A' if which_str == "File A" else 'B'
        features = self.pe_features_a if which == 'A' else self.pe_features_b

        if not features:
            self.pe_features_output.setPlainText("No features extracted yet. Run extraction from the toolbar.")
            self.resource_tree.clear()
            self.btn_generate_yara.setEnabled(False)
            return

        if "error" in features:
            self.pe_features_output.setPlainText(f"Error: {features['error']}")
            self.resource_tree.clear()
            self.btn_generate_yara.setEnabled(False)
            return

        # Display formatted JSON
        try:
            self.pe_features_output.setPlainText(json.dumps(features, indent=4))
            self.btn_generate_yara.setEnabled(True)
        except Exception as e:
            self.pe_features_output.setPlainText(f"Error formatting features: {e}")
            self.btn_generate_yara.setEnabled(False)

        # Populate resource tree
        self.resource_tree.clear()
        if features.get('resources'):
            for res in features['resources']:
                item = QtWidgets.QTreeWidgetItem([
                    str(res.get('type', 'N/A')),
                    str(res.get('id', 'N/A')),
                    str(res.get('lang', 'N/A')),
                    str(res.get('size', 'N/A')),
                    f"0x{res.get('offset', 0):X}"
                ])
                self.resource_tree.addTopLevelItem(item)
        
        self.pe_file_selector.currentTextChanged.connect(self.display_pe_features)


    def prepare_yargen_for_current_file(self):
        """Pre-populates the yarGen GUI with the current PE file and switches to it."""
        which_str = self.pe_file_selector.currentText()
        which = 'A' if which_str == "File A" else 'B'
        path = self.file_a_path if which == 'A' else self.file_b_path

        if not path:
            QtWidgets.QMessageBox.warning(self, "No File", f"File {which} is not loaded or has no path.")
            return

        # Pre-populate the yarGen tab fields
        self.yargen_malware_path.setText(path)
        suggested_output = os.path.join(os.path.dirname(path), f"{Path(path).stem}_rules.yar")
        self.yargen_output_file.setText(suggested_output)

        # Switch to the yarGen GUI tab
        yargen_tab_index = -1
        for i in range(self.main_tabs.count()):
            if self.main_tabs.widget(i) == self.yargen_widget:
                 yargen_tab_index = i
                 break

        if yargen_tab_index != -1:
            self.main_tabs.setCurrentIndex(yargen_tab_index)
            self.lbl_status.setText(f"yarGen GUI is ready for {os.path.basename(path)}. Adjust settings and click 'Run yarGen'.")
        else:
            logging.error("Could not find the yarGen GUI tab.")

    def run_detectiteasy_scan(self):
        """Runs DetectItEasy on the selected file."""
        which_str, ok = QtWidgets.QInputDialog.getItem(self, "Select Target", "Run DiE on:", ["File A", "File B"], 0, False)
        if not ok:
            return
            
        which = 'A' if which_str == "File A" else 'B'
        path = self.file_a_path if which == 'A' else self.file_b_path

        if not path:
            QtWidgets.QMessageBox.warning(self, "No File", f"File {which} is not loaded.")
            return

        die_path = os.path.join(script_dir, "detectiteasy", "diec.exe")
        if not os.path.exists(die_path):
             QtWidgets.QMessageBox.warning(self, "DiE Not Found", f"Could not find diec.exe at: {die_path}")
             return

        command = [die_path, "-j", path]
        self.run_generic_subprocess(command, self.die_output)


    def clear_all(self):
        """Reset the application state."""
        self.file_a_path = self.file_b_path = self.yara_path = None
        self.file_a_data = self.file_b_data = None
        self.pe_features_a = self.pe_features_b = None
        self.matches_a = self.matches_b = []
        self.capa_matches = []
        self.diff_hunks = []
        self.yara_index = {}
        self._yara_keys = []
        self.match_idx_a = self.match_idx_b = -1
        
        self.hunk_list.clear()
        self.yara_list.clear()
        self.capa_list.clear()
        self.hex_a.clear()
        self.hex_b.clear()
        self.asm_a.clear()
        self.asm_b.clear()
        self.details.clear()
        self.yara_editor.clear()
        self.capa_editor.clear()
        self.pe_features_output.clear()
        self.resource_tree.clear()
        self.die_output.clear()
        self.clamav_console.clear()
        self.clamav_db_path.clear()
        self.clamav_sig_input.clear()
        self.btn_generate_yara.setEnabled(False)
        
        self.lbl_status.setText("Cleared All")

    # --- Detail Views ---
    def _show_hunk_details(self, h: Dict):
        off, ln = h['start'], h['length']
        text = f"Hunk @ 0x{off:08X} (length {ln})\n"
        text += f"File A Size: {len(self.file_a_data) if self.file_a_data else 'N/A'}\n"
        text += f"File B Size: {len(self.file_b_data) if self.file_b_data else 'N/A'}"
        self.details.setPlainText(text)

    def _show_yara_details(self, key: Tuple):
        val = self.yara_index.get(key, {})
        rule, ident = key
        text = f"Rule: {rule}\nIdentifier: {ident}\n\n"
        a_offs = val.get('a_offsets', [])
        b_offs = val.get('b_offsets', [])
        text += f"Matches in A ({len(a_offs)}): {', '.join(f'0x{x:X}' for x in a_offs[:5])}{'...' if len(a_offs) > 5 else ''}\n"
        text += f"Matches in B ({len(b_offs)}): {', '.join(f'0x{x:X}' for x in b_offs[:5])}{'...' if len(b_offs) > 5 else ''}"
        self.details.setPlainText(text)

    def add_excluded_directory(self):
        """Opens a dialog to select a directory of YARA rules to exclude."""
        dir_path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Directory to Exclude")
        if dir_path:
            self.excluded_rules_list.addItem(dir_path)
            self.load_excluded_rules()

    def remove_selected_excluded(self):
        """Removes the selected directory from the excluded list."""
        for item in self.excluded_rules_list.selectedItems():
            self.excluded_rules_list.takeItem(self.excluded_rules_list.row(item))
        self.load_excluded_rules()

    def load_excluded_rules(self):
        """Loads all YARA rule names from the excluded directories."""
        self.excluded_rules = set()
        if not os.path.exists(excluded_rules_dir):
            os.makedirs(excluded_rules_dir)
            
        for i in range(self.excluded_rules_list.count()):
            dir_path = self.excluded_rules_list.item(i).text()
            if os.path.isdir(dir_path):
                for filename in os.listdir(dir_path):
                    if filename.endswith((".yar", ".yara")):
                        rule_path = os.path.join(dir_path, filename)
                        try:
                            with open(rule_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            # A simple regex to find rule names. This might not cover all edge cases.
                            rule_names = re.findall(r"rule\s+([a-zA-Z0-9_]+)", content)
                            self.excluded_rules.update(rule_names)
                        except Exception as e:
                            logging.error(f"Error reading excluded rule file {rule_path}: {e}")
        
        self.lbl_status.setText(f"Loaded {len(self.excluded_rules)} excluded YARA rules.")


# --- Application Entry Point ---
def main():
    """Main function to create and run the application."""
    app = QtWidgets.QApplication(sys.argv)
    win = OpenHydraFileAnalyzer()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
