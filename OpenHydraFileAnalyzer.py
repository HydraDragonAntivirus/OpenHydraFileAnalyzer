#!/usr/bin/env python3
"""
OpenHydraFileAnalyzer - PySide6 single-file application

A comprehensive file analysis tool with features for comparing, editing,
and analyzing binary files.

Features:
 - Dual-pane file loading (File A / File B) for comparison.
 - Unified Disassembly View: Side-by-side hex/ASCII dump and corresponding assembly.
 - File Roadmap: A graphical, color-coded map of the entire file structure with zoom.
 - Assembly Roadmap: A control-flow graph of executable sections.
 - Function Call View: An interactive view visualizing PE file imports, DLLs, and specific functions.
 - YARA-X rule loading, scanning, and a detailed match list.
 - Advanced YARA editor with syntax highlighting, saving, and validation.
 - CAPA integration for automated capability analysis with a structured match list.
 - CAPA rule editor with syntax highlighting.
 - yarGen integration with a full GUI to generate YARA rules from samples.
 - ClamAV SigTool integration for inspecting and decoding signature database files.
 - Computation and highlighting of differences (diff hunks) between files.
 - Light and Dark theme support.
 - Byte-level editing via a dialog or direct input controls.
 - Capstone-powered disassembly that updates automatically after edits.
 - Session persistence (saves last used file paths and settings).
 - DetectItEasy integration for packer/compiler identification.
 - Pefile-based feature extractor for detailed PE analysis.
 - Resource Viewer to inspect PE resources in a tree structure.
 - Unicorn Engine-based emulator for unpacking and analyzing packed files.
"""

import sys
import os
import subprocess
import logging
import binascii
import json
import re
import hashlib
import base64
import math
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
import struct
import lzma
from dataclasses import dataclass
import tempfile
import time


from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt, QPointF, QThreadPool, QRunnable, Slot, Signal, QObject
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont, QPainter, QPen, QBrush, QPainterPath, QPolygonF
from PySide6.QtWidgets import QGraphicsView, QGraphicsScene, QGraphicsRectItem, QGraphicsTextItem, QGraphicsItem, QGraphicsPathItem, QGraphicsLineItem, QTableWidgetItem

# PE file format constants for VMProtect unpacking
IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE\0\0
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
LZMA_PROPERTIES_SIZE = 5  # Standard LZMA properties size

@dataclass
class PACKER_INFO:
    """VMProtect packer info structure"""
    Src: int  # uint32
    Dst: int  # uint32

# --- Dependency Checks and Imports ---

try:
    import yara_x
    YARA_AVAILABLE = True
except ImportError:
    yara_x = None
    YARA_AVAILABLE = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_OP_IMM
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

try:
    # Import Unicorn Engine constants
    from unicorn import *
    from unicorn.x86_const import *
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False

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
capa_rules_dir = os.path.join(script_dir, "capa-rules")
capa_results_dir = os.path.join(script_dir, "capa_results")
excluded_rules_dir = os.path.join(script_dir, "excluded-rules")


# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Worker Thread for Background Tasks ---

class WorkerSignals(QObject):
    '''
    Defines the signals available from a running worker thread.
    Supported signals are:
    finished
        No data
    error
        `tuple` (exctype, value, traceback.format_exc())
    result
        `object` data returned from processing, anything
    progress
        `int` indicating % progress
    '''
    finished = Signal()
    error = Signal(tuple)
    result = Signal(object)
    progress = Signal(int)
    console_output = Signal(str)

class Worker(QRunnable):
    '''
    Worker thread
    Inherits from QRunnable to handler worker thread setup, signals and wrap-up.
    :param callback: The function callback to run on this worker thread. Supplied args and
                     kwargs will be passed through to the runner.
    :type callback: function
    :param args: Arguments to pass to the callback function
    :param kwargs: Keywords to pass to the callback function
    '''

    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()
        # Store constructor arguments (re-used for thread pooling)
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

        # Add the callback to our kwargs
        if 'progress_callback' not in self.kwargs:
            self.kwargs['progress_callback'] = self.signals.progress
        if 'console_output_callback' not in self.kwargs:
            self.kwargs['console_output_callback'] = self.signals.console_output


    @Slot()
    def run(self):
        '''
        Initialise the runner function with passed args, kwargs.
        '''
        # Retrieve args/kwargs here; and fire processing using them
        try:
            result = self.fn(*self.args, **self.kwargs)
        except:
            import traceback
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)  # Return the result of the processing
        finally:
            self.signals.finished.emit()  # Done

# --- Custom Zoomable Graphics View ---
class ZoomableView(QGraphicsView):
    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)

    def wheelEvent(self, event):
        zoom_in_factor = 1.25
        zoom_out_factor = 1 / zoom_in_factor

        if event.angleDelta().y() > 0:
            self.scale(zoom_in_factor, zoom_in_factor)
        else:
            self.scale(zoom_out_factor, zoom_out_factor)

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
                    'dll_name': entry.dll.decode() if entry.dll else "Unknown DLL",
                    'imports': [{
                        'name': imp.name.decode(errors='ignore') if imp.name else f"Ordinal {imp.ordinal}",
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
                    'name': exp.name.decode(errors='ignore') if exp.name else f"Ordinal {exp.ordinal}",
                    'address': exp.address,
                    'ordinal': exp.ordinal,
                    'forwarder': exp.forwarder.decode(errors='ignore') if exp.forwarder else None
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
        if file_path in self.features_cache:
            return self.features_cache[file_path]
            
        try:
            # Load the PE file
            pe = pefile.PE(file_path, fast_load=True)

            # Extract features
            numeric_features = {
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
                'sections': [self.extract_section_data(s) for s in pe.sections],
                'imports': self.extract_imports(pe),
                'exports': self.extract_exports(pe),
                'resources': [
                    {
                        'type_id': getattr(getattr(resource_type, 'struct', None), 'Id', None),
                        'resource_id': getattr(getattr(resource_id, 'struct', None), 'Id', None),
                        'lang_id': getattr(getattr(resource_lang, 'struct', None), 'Id', None),
                        'size': getattr(getattr(resource_lang, 'data', None), 'Size', None),
                        'codepage': getattr(getattr(resource_lang, 'data', None), 'CodePage', None),
                    }
                    for resource_type in
                    (pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries') else [])
                    for resource_id in (resource_type.directory.entries if hasattr(resource_type, 'directory') else [])
                    for resource_lang in (resource_id.directory.entries if hasattr(resource_id, 'directory') else [])
                    if hasattr(resource_lang, 'data')
                ],
                'debug': [
                    {
                        'type': debug.struct.Type,
                        'timestamp': debug.struct.TimeDateStamp,
                        'version': f"{debug.struct.MajorVersion}.{debug.struct.MinorVersion}",
                        'size': debug.struct.SizeOfData,
                    }
                    for debug in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', [])
                ],
                'certificates': self.analyze_certificates(pe),
                'dos_stub': self.analyze_dos_stub(pe),
                'tls_callbacks': self.analyze_tls_callbacks(pe),
                'delay_imports': self.analyze_delay_imports(pe),
                'load_config': self.analyze_load_config(pe),
                'bound_imports': self.analyze_bound_imports(pe),
                'section_characteristics': self.analyze_section_characteristics(pe),
                'extended_headers': self.analyze_extended_headers(pe),
                'rich_header': self.analyze_rich_header(pe),
                'overlay': self.analyze_overlay(pe, file_path),
                'relocations': self.analyze_relocations(pe)
            }

            if rank is not None:
                numeric_features['numeric_tag'] = rank
            
            self.features_cache[file_path] = numeric_features
            return numeric_features

        except Exception as ex:
            logging.error(f"Error extracting numeric features from {file_path}: {str(ex)}", exc_info=True)
            return {'error': str(ex)}

class EnhancedUnicornUnpacker:
    def __init__(self, file_path, console_output_callback=None):
        self.file_path = file_path
        self.console_output = console_output_callback
        self.pe = None
        self.mu = None
        self.oep = None
        self.initial_sections_info = {}
        self.vmprotect_data = None
        self.instruction_count = 0
        self.max_instructions_before_check = 5000  # More frequent checks
        self.unpacker_sections = set()
        self.original_entry_point = None
        self.execution_history = []
        self.potential_oeps = []
        self.page_log_interval = 0x1000   # throttle per page
        self.logged_pages = set()
        # Stall detection
        self.last_progress_time = time.time()
        self.last_instruction_count = 0
        self.stall_timeout = 10 # seconds
        self.page_fault_count = 0
        self.max_page_faults = 500 # Limit to prevent infinite mapping
        # Packer-specific flags
        self.is_upx_packed = False


    def log(self, message: str):
        logging.info(message)
        if self.console_output:
            try:
                # Support both Qt signals and simple callables
                emit = getattr(self.console_output, 'emit', None)
                if callable(emit):
                    emit(message)
                elif callable(self.console_output):
                    self.console_output(message)
            except Exception:
                pass

    def to_hex_string(self, val, prefix=True):
        return f"0x{val:x}" if prefix else f"{val:x}"

    def dump_executed_pages(self, out_dir):
        """Dump memory pages that were executed (from logged_pages) to files for offline analysis."""
        if not self.mu:
            self.log("[Dump] No emulator instance available")
            return
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            pass

        for page in sorted(self.logged_pages):
            try:
                data = self.mu.mem_read(page, 0x1000)
                fname = os.path.join(out_dir, f"page_{page:08x}.bin")
                with open(fname, "wb") as f:
                    f.write(data)
                self.log(f"[Dump] Wrote page 0x{page:x} to {fname}")
            except Exception as e:
                self.log(f"[Dump] Failed to dump page 0x{page:x}: {e}")

    def find_pattern(self, data: bytes, pattern: bytes) -> Optional[int]:
        """
        Find pattern in data, supporting 0xFF as wildcard
        Returns position where found, or None if not found
        """
        if not pattern or len(data) < len(pattern):
            return None

        for i in range(len(data) - len(pattern) + 1):
            match = True
            for j in range(len(pattern)):
                if pattern[j] != 0xFF and data[i + j] != pattern[j]:
                    match = False
                    break
            if match:
                return i
        return None

    def _parse_lzma_props(self, lzma_props_data):
        """Return (lc, lp, pb, dict_size) or None if invalid."""
        if not lzma_props_data or len(lzma_props_data) < 5:
            return None
        first = lzma_props_data[0]
        if first > 224:
            return None
        lc = first % 9
        lp = (first // 9) % 5
        pb = first // 45
        dict_size = int.from_bytes(lzma_props_data[1:5], 'little')
        # Keep dict size sane (4KB..64MB)
        if dict_size < 4096 or dict_size > 0x4000000:  # 64MB cap
            return None
        return lc, lp, pb, dict_size

    def _sync_to_lzma_stream(self, blob: bytes, lc: int, lp: int, pb: int, dict_size: int,
                            max_lookahead: int = 0x4000, test_bytes: int = 4096):
        """
        Try to locate the start of a valid raw LZMA stream within the first max_lookahead bytes.
        Returns (offset, 'LZMA1'|'LZMA2') or (None, None).
        Treats 'Already at end of stream' as a benign probe result (some streams are short).
        """
        limit = min(len(blob), max_lookahead)
        for off in range(0, limit):
            window = blob[off: off + test_bytes]
            if not window:
                break

            # LZMA1 probe
            try:
                d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{
                    "id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb
                }])
                _ = d.decompress(window)
                return off, 'LZMA1'
            except lzma.LZMAError as e:
                # treat "Already at end of stream" as a valid probe (short stream)
                if 'Already at end of stream' in str(e):
                    return off, 'LZMA1'
                pass

            # LZMA2 probe
            try:
                d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{
                    "id": lzma.FILTER_LZMA2, "dict_size": dict_size
                }])
                _ = d.decompress(window)
                return off, 'LZMA2'
            except lzma.LZMAError as e:
                if 'Already at end of stream' in str(e):
                    return off, 'LZMA2'
                pass

        return None, None

    def extract_vmprotect_data(self, pe_data: bytes):
        """Enhanced VMProtect LZMA compressed data extraction with better error handling"""
        if pefile is None:
            self.log("[VMProtect] pefile module not available")
            return None

        try:
            pe = pefile.PE(data=pe_data)
        except pefile.PEFormatError as e:
            self.log(f"[VMProtect] Invalid PE file format: {str(e)}")
            return None

        is_64bit = pe.FILE_HEADER.Machine == 0x8664

        vmprotect_sections = []
        for section in pe.sections:
            sec_name = section.Name.decode(errors='ignore').strip('\x00')
            if any(vmp_name in sec_name.lower() for vmp_name in ['.vmp', '.text', '.data', '.rdata']):
                vmprotect_sections.append(section)

        self.log(f"[VMProtect] Found {len(vmprotect_sections)} potential VMProtect sections")

        rva_patterns_array = []
        valid_sections = []

        for section in pe.sections:
            condition1 = (section.SizeOfRawData == 0)
            condition2 = (section.PointerToRawData == 0)
            condition3 = not (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            condition4 = (section.VirtualAddress > 0 and section.Misc_VirtualSize > 0)

            if condition1 and condition2 and condition3 and condition4:
                valid_sections.append(section)
                if is_64bit:
                    pattern_value = ((section.VirtualAddress << 32) | 0xFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
                    pattern_bytes = struct.pack("<Q", pattern_value)
                else:
                    pattern_bytes = struct.pack("<I", section.VirtualAddress) + b'\xFF\xFF\xFF\xFF'
                rva_patterns_array.append(pattern_bytes)

        if not rva_patterns_array:
            self.log("[VMProtect] No VMProtect RVA patterns found")
            return None

        self.log(f"[VMProtect] Found {len(rva_patterns_array)} RVA patterns from {len(valid_sections)} sections")

        pattern_bytes = b''.join(rva_patterns_array)
        pattern_pos = self.find_pattern(pe_data, pattern_bytes)

        if pattern_pos is not None:
            if pattern_pos < 8:
                self.log("[VMProtect] Located RVA pattern is too close to the beginning")
                return None

            packer_info_offset = pattern_pos - 8
            num_packer_entries = len(rva_patterns_array)
            required_size = (num_packer_entries + 1) * 8
            if packer_info_offset + required_size > len(pe_data):
                self.log(f"[VMProtect] PACKER_INFO array extends beyond file (need {required_size} bytes, have {len(pe_data) - packer_info_offset})")
                return None

            packer_info_array = []
            for j in range(num_packer_entries + 1):
                info_offset = packer_info_offset + j * 8
                src = struct.unpack("<I", pe_data[info_offset:info_offset+4])[0]
                dst = struct.unpack("<I", pe_data[info_offset+4:info_offset+8])[0]
                packer_info_array.append(PACKER_INFO(src, dst))

            self.log(f"[VMProtect] Found {len(packer_info_array)} PACKER_INFO entries ({'64-bit' if is_64bit else '32-bit'} PE)")

            return {
                'pe': pe,
                'packer_info': packer_info_array,
                'pe_data': pe_data,
                'is_64bit': is_64bit,
                'packer_info_offset': packer_info_offset
            }

        return None

    def debug_vmprotect_structure(self, vmprotect_data) -> bool:
        """Debug VMProtect structure to understand why LZMA extraction fails
        Returns True if it made a correction to packer_info (partial properties), False otherwise.
        """
        if not vmprotect_data:
            return False

        pe = vmprotect_data['pe']
        packer_info_array = vmprotect_data['packer_info']
        pe_data = vmprotect_data['pe_data']

        self.log("[VMProtect Debug] Analyzing PACKER_INFO structure:")

        for i, info in enumerate(packer_info_array):
            self.log(f"  Entry {i}: Src=0x{info.Src:x}, Dst=0x{info.Dst:x}")

            if i == 0:  # Properties entry
                try:
                    props_offset = pe.get_offset_from_rva(info.Src)
                    self.log(f"    Properties offset: 0x{props_offset:x}")
                    self.log(f"    Properties size: {info.Dst}")
                    self.log(f"    File size: {len(pe_data)}")

                    if props_offset + info.Dst <= len(pe_data):
                        props_data = pe_data[props_offset:props_offset + min(16, info.Dst)]
                        self.log(f"    Properties data (first 16 bytes): {props_data.hex()}")
                    else:
                        self.log(f"    Properties extend beyond file by {(props_offset + info.Dst) - len(pe_data)} bytes")

                        if props_offset < len(pe_data):
                            available_size = len(pe_data) - props_offset
                            props_data = pe_data[props_offset:props_offset + available_size]
                            self.log(f"    Available properties data ({available_size} bytes): {props_data.hex()}")

                            if available_size >= 5:
                                self.log("    Attempting to use partial properties data...")
                                corrected_info = PACKER_INFO(info.Src, available_size)
                                vmprotect_data['packer_info'][0] = corrected_info
                                return True

                except Exception as e:
                    self.log(f"    Error accessing properties: {str(e)}")
            else:  # Data blocks
                try:
                    block_offset = pe.get_offset_from_rva(info.Src)
                    self.log(f"    Block {i} offset: 0x{block_offset:x}, target RVA: 0x{info.Dst:x}")

                    if block_offset < len(pe_data):
                        sample_size = min(16, len(pe_data) - block_offset)
                        sample_data = pe_data[block_offset:block_offset + sample_size]
                        self.log(f"    Block {i} data sample: {sample_data.hex()}")
                    else:
                        self.log(f"    Block {i} offset beyond file")

                except Exception as e:
                    self.log(f"    Error accessing block {i}: {str(e)}")

        return False  # No correction made

    def _find_lzma_props_by_scan(self, pe, pe_data, hint_offset=None, search_range=0x2000):
        """
        Search pe_data for plausible LZMA props (5 bytes). Returns (props_rva, props_size) or (None, None).
        LZMA props: 1 byte (lc/lp/pb) where <=224, followed by 4-byte little-endian dict size.
        If hint_offset is given, search nearby first, then whole file (bounded by search_range).
        """
        file_len = len(pe_data)
        candidates = []

        def check_offset(o):
            if o + 5 > file_len:
                return False
            first = pe_data[o]
            if first > 224:
                return False
            dict_size = int.from_bytes(pe_data[o+1:o+5], 'little')
            if dict_size < 4096 or dict_size > 0x4000000:  # cap at 64MB
                return False
            return True

        if hint_offset is not None:
            start = max(0, hint_offset - search_range)
            end = min(file_len - 5, hint_offset + search_range)
            for o in range(start, end):
                if check_offset(o):
                    candidates.append(o)

        if not candidates:
            max_scan = min(file_len - 5, 5 * 1024 * 1024)  # scan up to first 5MB
            for o in range(0, max_scan):
                if check_offset(o):
                    candidates.append(o)
                    break

        for raw_off in candidates:
            try:
                rva = pe.get_rva_from_offset(raw_off)
                return (rva, int.from_bytes(pe_data[raw_off+1:raw_off+5], 'little'))
            except Exception:
                return (None, int.from_bytes(pe_data[raw_off+1:raw_off+5], 'little'))

        return (None, None)

    def decompress_vmprotect_lzma(self, vmprotect_data) -> Optional[Dict[int, bytes]]:
        """Decompress VMProtect LZMA blocks into {rva: data} dict (returns None on failure)."""
        if not vmprotect_data or len(vmprotect_data.get('packer_info', [])) <= 1:
            self.log("[VMProtect] Insufficient packer_info for LZMA decompression.")
            return None

        pe = vmprotect_data['pe']
        packer_info_array = vmprotect_data['packer_info']
        pe_data = vmprotect_data['pe_data']

        props_info = packer_info_array[0]
        try:
            props_raw_offset = pe.get_offset_from_rva(props_info.Src)
        except Exception:
            self.log(f"[VMProtect] Cannot get properties offset for RVA {self.to_hex_string(props_info.Src)}. Scanning for properties...")
            hint = vmprotect_data.get('packer_info_offset', None)
            found_rva, _ = self._find_lzma_props_by_scan(pe, pe_data, hint_offset=hint)
            if found_rva is None:
                self.log("[VMProtect] Scan for LZMA properties failed. Cannot decompress.")
                return None
            
            try:
                props_raw_offset = pe.get_offset_from_rva(found_rva)
                dict_size = int.from_bytes(pe_data[props_raw_offset+1:props_raw_offset+5], 'little')
                props_info = PACKER_INFO(found_rva, dict_size)
                vmprotect_data['packer_info'][0] = props_info # Correct the info for later use
                self.log(f"[VMProtect] Found fallback properties at RVA 0x{found_rva:x}")
            except Exception:
                 self.log("[VMProtect] Cannot use fallback properties. Decompression aborted.")
                 return None

        lzma_props_size = 5
        if props_raw_offset < 0 or props_raw_offset + lzma_props_size > len(pe_data):
            self.log(f"[VMProtect] Properties offset/size invalid (offset={props_raw_offset}, size={lzma_props_size})")
            return None

        lzma_props_data = pe_data[props_raw_offset:props_raw_offset + lzma_props_size]
        parsed = self._parse_lzma_props(lzma_props_data)
        if not parsed:
            self.log("[VMProtect] LZMA properties invalid after sanity checks.")
            return None

        lc, lp, pb, dict_size = parsed
        self.log(f"[VMProtect] LZMA props: lc={lc}, lp={lp}, pb={pb}, dict_size=0x{dict_size:x}")
        decompressed_sections: Dict[int, bytes] = {}

        total_blocks = len(packer_info_array) - 1
        for block_idx in range(1, len(packer_info_array)):
            # Log progress to keep the user informed
            if block_idx % 5 == 0 or total_blocks < 10:
                 self.log(f"[VMProtect] Decompressing block {block_idx}/{total_blocks}...")

            current_block_info = packer_info_array[block_idx]
            compressed_data_rva = current_block_info.Src
            uncompressed_target_rva = current_block_info.Dst

            if compressed_data_rva == 0 or uncompressed_target_rva == 0:
                self.log(f"[VMProtect] Block {block_idx}: Skipping invalid block (Src or Dst is zero).")
                continue

            try:
                compressed_block_raw_offset = pe.get_offset_from_rva(compressed_data_rva)
            except Exception:
                self.log(f"[VMProtect] Block {block_idx}: Cannot convert RVA {self.to_hex_string(compressed_data_rva)} to offset. Skipping.")
                continue

            if compressed_block_raw_offset >= len(pe_data):
                self.log(f"[VMProtect] Block {block_idx}: Compressed data offset {compressed_block_raw_offset} is beyond file size. Skipping.")
                continue

            max_compressed_size = min(0x2000000, len(pe_data) - compressed_block_raw_offset)
            compressed_data = pe_data[compressed_block_raw_offset : compressed_block_raw_offset + max_compressed_size]

            if len(compressed_data) < 10:
                self.log(f"[VMProtect] Block {block_idx}: Compressed data too small ({len(compressed_data)} bytes). Skipping.")
                continue

            start_off, kind = self._sync_to_lzma_stream(compressed_data, lc, lp, pb, dict_size)
            if start_off is None:
                self.log(f"[VMProtect] Block {block_idx}: Could not sync to a valid LZMA stream. Skipping.")
                continue
            
            stream_data = compressed_data[start_off:]
            
            # --- Chunked Decompression to prevent freezing ---
            try:
                filters: List[Dict[str, Any]]
                if kind == 'LZMA1':
                    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}]
                else: # LZMA2
                    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}]

                decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
                
                output_chunks = []
                total_decompressed_size = 0
                max_output_size = 0x4000000 # 64MB limit per block
                input_chunk_size = 65536  # Process 64KB of compressed data at a time

                for i in range(0, len(stream_data), input_chunk_size):
                    chunk = stream_data[i:i + input_chunk_size]
                    if not chunk:
                        break
                    
                    try:
                        decompressed_chunk = decompressor.decompress(chunk, max_length=max_output_size - total_decompressed_size)
                        if decompressed_chunk:
                            output_chunks.append(decompressed_chunk)
                            total_decompressed_size += len(decompressed_chunk)
                        
                        if total_decompressed_size >= max_output_size:
                            self.log(f"[VMProtect] Block {block_idx}: Decompression output limit reached.")
                            break
                    except lzma.LZMAError as e:
                        if "end of stream" in str(e).lower():
                            break # This is an expected way to finish
                        else:
                            self.log(f"[VMProtect] Block {block_idx}: LZMA error during chunked decompression: {e}")
                            output_chunks = [] # Invalidate partial data on real error
                            break
                
                if output_chunks:
                    decompressed_data = b"".join(output_chunks)
                    decompressed_sections[uncompressed_target_rva] = decompressed_data
                else:
                    # This is not an error, some blocks might be empty
                    pass

            except MemoryError:
                self.log(f"[VMProtect] Block {block_idx}: Out of memory during decompression. Skipping.")
            except Exception as e:
                self.log(f"[VMProtect] Block {block_idx}: Unexpected error during chunked decompression: {repr(e)}")

        if decompressed_sections:
            self.log(f"[VMProtect] Successfully decompressed {len(decompressed_sections)} sections.")
        else:
            self.log("[VMProtect] Decompression finished, but no sections were recovered.")

        return decompressed_sections

    def analyze_instruction(self, address, data):
        """Analyze instruction to detect potential OEP patterns"""
        try:
            if len(data) >= 2:
                if data[0] in [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57]:
                    return "push_pattern"
                elif data[0] in [0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F]:
                    return "pop_pattern"
                elif data[0] == 0xE8:
                    return "call_pattern"
                elif data[0] == 0xE9:
                    return "jmp_pattern"
                elif data[0:2] == b'\x8B\xFF':
                    return "windows_pattern"
                elif data[0] == 0x55 and len(data) > 1 and data[1] == 0x8B:
                    return "function_prologue"
        except Exception:
            pass
        return None

    def hook_code(self, uc, address, size, user_data):
        # Count instructions for progress tracking
        self.instruction_count += 1

        # Store execution history for analysis (avoid duplicates)
        if len(self.execution_history) < 1000:
            if not self.execution_history or self.execution_history[-1] != address:
                self.execution_history.append(address)

        # Periodically log progress and check for stalls
        if self.instruction_count % self.max_instructions_before_check == 0:
            current_time = time.time()
            if current_time - self.last_progress_time > self.stall_timeout:
                if self.instruction_count - self.last_instruction_count < self.max_instructions_before_check:
                    self.log("[!] Stall detected! Emulation progress is too slow. Stopping.")
                    uc.emu_stop()
                    return
            self.last_progress_time = current_time
            self.last_instruction_count = self.instruction_count
            self.log(f"[Progress] Executed {self.instruction_count} instructions, current address: 0x{address:x}")

        # UPX-specific OEP detection. This is a high-confidence pattern.
        if self.is_upx_packed and self.oep is None:
            try:
                inst_bytes = uc.mem_read(address, 1)
                # Check for POPAD instruction (opcode 0x61)
                if inst_bytes[0] == 0x61:
                    self.log(f"[UPX] POPAD instruction found at 0x{address:x}")
                    
                    # The instruction after POPAD is the jump to OEP.
                    next_inst_addr = address + 1
                    # Read enough bytes for a potential JMP rel32 instruction (5 bytes)
                    next_inst_bytes = uc.mem_read(next_inst_addr, 5)

                    # Check for a long jump (E9 JMP rel32)
                    if next_inst_bytes[0] == 0xE9:
                        rel_offset = struct.unpack('<i', next_inst_bytes[1:5])[0]
                        # OEP = address of instruction after JMP + relative offset
                        self.oep = (next_inst_addr + 5) + rel_offset
                        self.log(f"[UPX] Found JMP to OEP at 0x{self.oep:x}")
                        uc.emu_stop()
                        return # Stop further processing in this hook
            except Exception:
                # This can happen if we read near unmapped memory, just ignore.
                pass

        # Enhanced OEP detection with VMProtect awareness
        if self.oep is None and self.pe is not None:
            try:
                image_base = self.pe.OPTIONAL_HEADER.ImageBase
                image_size = self.pe.OPTIONAL_HEADER.SizeOfImage

                # Read instruction bytes for analysis
                try:
                    inst_data = uc.mem_read(address, min(size, 16))
                    pattern = self.analyze_instruction(address, inst_data)

                    if pattern:
                        try:
                            section = self.pe.get_section_by_rva(address - image_base)
                            if section:
                                sec_name = section.Name.decode(errors='ignore').strip('\x00')

                                # Skip VMProtect sections
                                if any(vmp in sec_name.lower() for vmp in ['.vmp', '.upx', '.themida']):
                                    return

                                if sec_name in ['.text', '.code', 'CODE'] and pattern in ['function_prologue', 'windows_pattern']:
                                    self.potential_oeps.append({
                                        'address': address,
                                        'pattern': pattern,
                                        'section': sec_name,
                                        'confidence': 0.8
                                    })
                                    self.log(f"[OEP Candidate] Found {pattern} in {sec_name} at 0x{address:x}")

                                    if len(self.potential_oeps) >= 3 or pattern == 'windows_pattern':
                                        self.oep = address
                                        self.log(f"[!] High confidence OEP detected at 0x{address:x}")
                                        uc.emu_stop()
                                        return
                        except Exception:
                            pass

                except Exception:
                    pass

                # Check for execution outside original image (unpacked code)
                if address < image_base or address >= (image_base + image_size):
                    # Throttle logs by page address to avoid floods
                    page = address & ~(self.page_log_interval - 1)
                    if page not in self.logged_pages:
                        self.logged_pages.add(page)
                        self.log(f"[!] Execution outside original image at 0x{address:x} (page 0x{page:x})")
                        # Also check whether this page looks like contains an in-memory PE header:
                        try:
                            page_data = uc.mem_read(page, min(0x1000, 0x1000))
                            if page_data.startswith(b'MZ') or b'This program cannot be run in DOS mode' in page_data[:0x400]:
                                # Very strong candidate: an in-memory PE landed here
                                self.log(f"[OEP Candidate] Detected in-memory PE header at page 0x{page:x}, treating as OEP candidate")
                                try:
                                    self.potential_oeps.append({
                                        'address': page,
                                        'pattern': 'in_memory_pe',
                                        'section': 'unknown',
                                        'confidence': 0.9
                                    })
                                    self.oep = page
                                    uc.emu_stop()
                                    return
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    return

                # Check for section transitions
                try:
                    section = self.pe.get_section_by_rva(address - image_base)
                    if section:
                        sec_name = section.Name.decode(errors='ignore').strip('\x00')

                        # Track unpacker sections
                        if any(name in sec_name.lower() for name in ['.vmp', '.upx', '.themida', '.aspack']):
                            self.unpacker_sections.add(sec_name)
                            return

                        # Detect transition from unpacker to original code
                        if (len(self.unpacker_sections) > 0 and 
                            sec_name not in self.unpacker_sections and 
                            sec_name in ['.text', '.code', 'CODE', '.data', '.rdata']):

                            self.log(f"[!] Transition from unpacker to original section '{sec_name}' at 0x{address:x}")
                            self.potential_oeps.append({
                                'address': address,
                                'pattern': 'section_transition',
                                'section': sec_name,
                                'confidence': 0.9
                            })

                            if sec_name == '.text' or len(self.potential_oeps) >= 2:
                                self.oep = address
                                uc.emu_stop()
                                return

                except Exception as e:
                    if address >= image_base and address < (image_base + image_size):
                        self.log(f"[!] Execution at unmapped address 0x{address:x} within image")
                        self.potential_oeps.append({
                            'address': address,
                            'pattern': 'unmapped_execution',
                            'section': 'unknown',
                            'confidence': 0.6
                        })

                        if len(self.potential_oeps) >= 5:
                            self.oep = address
                            uc.emu_stop()

            except Exception as e:
                self.log(f"[Debug] Error in code hook: {str(e)}")

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        """Enhanced memory handler for VMProtect with aggressive (but safer) mapping"""
        self.page_fault_count += 1
        if self.page_fault_count > self.max_page_faults:
            if self.page_fault_count % 100 == 0: # Log every 100 faults after limit
                self.log(f"[Memory] Excessive page faults ({self.page_fault_count}), stopping to prevent infinite loop.")
            uc.emu_stop()
            return False

        # Throttle logging for frequent faults
        if self.page_fault_count % 50 != 0:
            logging.debug(f"[Memory] Invalid memory access at 0x{address:x} (size: {size}, access: {access})")
        else:
            self.log(f"[Memory] Invalid memory access at 0x{address:x} (size: {size}, access: {access}) - fault count: {self.page_fault_count}")


        try:
            # Handle null pointer access
            if address == 0:
                self.log("[Memory] Null pointer access - mapping null page")
                try:
                    uc.mem_map(0, 0x1000)
                    uc.mem_write(0, b'\x00' * 0x1000)
                    self.log("[Memory] Null page mapped successfully")
                    return True
                except Exception as e:
                    self.log(f"[Memory] Failed to map null page: {str(e)}")
                    return False

            # Align address to page boundary
            page_size = 0x1000
            aligned_addr = address & ~(page_size - 1)

            # Get image information
            image_base = self.pe.OPTIONAL_HEADER.ImageBase if self.pe else 0x400000

            # Safer mapping strategy: try single page, then small region
            try:
                # Check if already mapped
                try:
                    uc.mem_read(aligned_addr, 1)
                    return True
                except Exception:
                    pass

                if aligned_addr < 0x80000000:
                    # Special handling for very low addresses: map only the requested page
                    if aligned_addr < 0x1000 and aligned_addr > 0:
                        try:
                            uc.mem_map(aligned_addr, page_size)
                            uc.mem_write(aligned_addr, b'\x00' * page_size)
                            self.log(f"[Memory] Mapped low page at 0x{aligned_addr:x}")
                            return True
                        except Exception as e:
                            self.log(f"[Memory] Failed to map low page: {str(e)}")
                            return False

                    # Try to map the specific page
                    try:
                        uc.mem_map(aligned_addr, page_size)
                        uc.mem_write(aligned_addr, b'\x00' * page_size)
                        self.log(f"[Memory] Mapped page at 0x{aligned_addr:x}")
                        return True
                    except Exception as e:
                        self.log(f"[Memory] Failed to map page at 0x{aligned_addr:x}: {str(e)}")

                        # If single page fails, try mapping a slightly larger region
                        try:
                            region_size = 0x10000  # 64KB
                            region_base = aligned_addr & ~(region_size - 1)
                            if region_base + region_size <= 0x80000000:
                                uc.mem_map(region_base, region_size)
                                uc.mem_write(region_base, b'\x00' * region_size)
                                self.log(f"[Memory] Mapped larger region at 0x{region_base:x} (size: 0x{region_size:x})")
                                return True
                        except Exception as e2:
                            self.log(f"[Memory] Failed to map larger region: {str(e2)}")

                        return False
                else:
                    self.log(f"[Memory] Address 0x{aligned_addr:x} too high for 32-bit emulation")
                    return False

            except Exception as e:
                self.log(f"[Memory] Exception in memory mapping: {str(e)}")
                return False

        except Exception as e:
            self.log(f"[Memory] Exception in memory handler: {str(e)}")
            return False

    # Aliases for unmapped hooks
    def hook_mem_read_unmapped(self, uc, access, address, size, value, user_data):
        return self.hook_mem_invalid(uc, access, address, size, value, user_data)

    def hook_mem_write_unmapped(self, uc, access, address, size, value, user_data):
        return self.hook_mem_invalid(uc, access, address, size, value, user_data)

    def hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        return self.hook_mem_invalid(uc, access, address, size, value, user_data)

    def unpack(self, timeout=30, max_instructions=2000000):
        self.log("Starting enhanced unpacking process...")

        # First, try static VMProtect extraction with better error handling
        try:
            with open(self.file_path, 'rb') as f:
                pe_data = f.read()

            self.vmprotect_data = self.extract_vmprotect_data(pe_data)
            if self.vmprotect_data:
                self.log("[VMProtect] Detected VMProtect patterns, attempting static extraction...")

                # Debug the VMProtect structure
                try:
                    corrected = self.debug_vmprotect_structure(self.vmprotect_data)
                except Exception as e:
                    self.log(f"[VMProtect] Debugging exception: {e}")
                    corrected = False

                try:
                    decompressed_sections = self.decompress_vmprotect_lzma(self.vmprotect_data)
                except Exception as e:
                    self.log(f"[VMProtect] Decompression exception: {e}")
                    decompressed_sections = None
                if decompressed_sections and len(decompressed_sections) > 0:
                    self.log(f"[VMProtect] Successfully extracted {len(decompressed_sections)} compressed sections")
                    # Skip Unicorn if we already unpacked successfully
                    #return decompressed_sections
                else:
                    self.log("[VMProtect] Static extraction failed or produced no sections, relying on dynamic analysis")
            else:
                self.log("[VMProtect] No VMProtect patterns detected or extraction failed")
        except Exception as e:
            self.log(f"[VMProtect] Static extraction error: {str(e)}")

        # Continue with enhanced dynamic analysis
        if pefile is None:
            self.log("[!] pefile module not available - cannot continue dynamic analysis")
            return None

        try:
            self.pe = pefile.PE(self.file_path)
        except pefile.PEFormatError as e:
            self.log(f"[!] Error: Not a valid PE file. {e}")
            return None

        # Check for UPX sections to enable specialized logic
        self.is_upx_packed = False
        for section in self.pe.sections:
            sec_name = section.Name.decode(errors='ignore').strip('\x00')
            if 'upx' in sec_name.lower():
                self.is_upx_packed = True
                self.log("[UPX] Detected UPX packed file based on section names.")
                break

        # Store original entry point for reference
        self.original_entry_point = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

        # Determine architecture and set up Unicorn Engine
        machine_type = self.pe.FILE_HEADER.Machine
        is_64bit = False

        if machine_type == 0x014c:  # IMAGE_FILE_MACHINE_I386
            self.log("Detected 32-bit PE file")
            if Uc is None:
                self.log("[!] Unicorn not available - cannot emulate")
                return None
            self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
            is_64bit = False
        elif machine_type == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            self.log("Detected 64-bit PE file")
            if Uc is None:
                self.log("[!] Unicorn not available - cannot emulate")
                return None
            self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
            is_64bit = True
        else:
            self.log(f"[!] Error: Unsupported architecture. Machine type: 0x{machine_type:x}")
            return None

        try:
            image_base = self.pe.OPTIONAL_HEADER.ImageBase
            image_size = self.pe.OPTIONAL_HEADER.SizeOfImage

            # Enhanced memory layout for VMProtect
            aligned_image_size = (image_size + 0x1000 - 1) & ~(0x1000 - 1)
            # Reduced default extra space to reduce memory pressure
            extra_space = 0x1000000  # 16MB extra space for VMProtect (was 64MB)
            total_mapped_size = aligned_image_size + extra_space

            self.log(f"Enhanced memory layout:")
            self.log(f"  Image base: 0x{image_base:x}")
            self.log(f"  Image size: 0x{aligned_image_size:x}")
            self.log(f"  Extra space: 0x{extra_space:x}")
            self.log(f"  Total mapped: 0x{total_mapped_size:x}")

            # Map main memory region
            try:
                self.mu.mem_map(image_base, total_mapped_size)
                # Initialize extra space in manageable chunks
                chunk_size = 0x100000  # 1MB chunks
                for offset in range(0, extra_space, chunk_size):
                    actual_size = min(chunk_size, extra_space - offset)
                    self.mu.mem_write(image_base + aligned_image_size + offset, b'\x00' * actual_size)

                self.log("Successfully mapped main memory region")
            except Exception as e:
                self.log(f"[!] Failed to map memory: {str(e)}")
                return None

            # Store initial section information
            for section in self.pe.sections:
                sec_name = section.Name.decode(errors='ignore').strip('\x00')
                self.initial_sections_info[sec_name] = {
                    'executable': bool(section.Characteristics & 0x20000000),
                    'virtual_address': section.VirtualAddress,
                    'size': section.Misc_VirtualSize
                }

            # Enhanced PE data writing
            self.log("Writing PE data to memory with enhanced method...")
            pe_data = self.pe.write()

            try:
                # Write headers
                headers_size = self.pe.OPTIONAL_HEADER.SizeOfHeaders
                headers_data = bytes(pe_data[:headers_size])
                self.mu.mem_write(image_base, headers_data)
                self.log(f"Written PE headers: {len(headers_data)} bytes")

                # Write each section individually with validation
                for section in self.pe.sections:
                    if section.PointerToRawData > 0 and section.SizeOfRawData > 0:
                        try:
                            if section.PointerToRawData + section.SizeOfRawData <= len(pe_data):
                                section_data = pe_data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
                                section_data = bytes(section_data)

                                target_addr = image_base + section.VirtualAddress
                                if target_addr + len(section_data) <= image_base + total_mapped_size:
                                    self.mu.mem_write(target_addr, section_data)
                                    sec_name = section.Name.decode(errors='ignore').strip('\x00')
                                    self.log(f"Written section {sec_name}: {len(section_data)} bytes at 0x{target_addr:x}")
                                else:
                                    sec_name = section.Name.decode(errors='ignore').strip('\x00')
                                    self.log(f"Section {sec_name} extends beyond mapped memory, skipping")
                            else:
                                sec_name = section.Name.decode(errors='ignore').strip('\x00')
                                self.log(f"Section {sec_name} extends beyond PE data, skipping")
                        except Exception as sec_e:
                            sec_name = section.Name.decode(errors='ignore').strip('\x00')
                            self.log(f"Failed to write section {sec_name}: {str(sec_e)}")

                self.log("PE data written successfully")

            except Exception as e:
                self.log(f"Failed to write PE data: {str(e)}")
                return None

            # For in-place unpackers like UPX, ensure all sections are writable.
            if self.is_upx_packed:
                self.log("[UPX] Setting all sections to Read/Write/Execute for in-place unpacking.")
                try:
                    for section in self.pe.sections:
                        addr = image_base + section.VirtualAddress
                        size = (section.Misc_VirtualSize + 0xFFF) & ~0xFFF # Align to page size
                        self.mu.mem_protect(addr, size, UC_PROT_ALL)
                except Exception as e:
                    self.log(f"[!] Failed to change section permissions: {e}")


            # Write VMProtect decompressed sections if available
            if self.vmprotect_data:
                try:
                    decompressed_sections = self.decompress_vmprotect_lzma(self.vmprotect_data)
                except Exception as e:
                    self.log(f"[VMProtect] Decompression exception while writing: {e}")
                    decompressed_sections = None

                if decompressed_sections:
                    for rva, data in decompressed_sections.items():
                        try:
                            target_addr = image_base + rva
                            if target_addr + len(data) <= image_base + total_mapped_size:
                                section_data = bytes(data) if not isinstance(data, bytes) else data
                                self.mu.mem_write(target_addr, section_data)
                                self.log(f"[VMProtect] Wrote decompressed section to 0x{target_addr:x} ({len(section_data)} bytes)")
                            else:
                                self.log(f"[VMProtect] Decompressed section at RVA 0x{rva:x} extends beyond mapped memory")
                        except Exception as e:
                            self.log(f"[VMProtect] Failed to write decompressed section: {str(e)}")

            # Setup stack with better positioning
            stack_base = 0x7fff0000 if not is_64bit else 0x7fff00000000
            stack_size = 0x100000  # 1MB stack

            try:
                stack_mapped = False
                for stack_attempt in [stack_base, 0x12340000, 0x50000000]:
                    try:
                        self.mu.mem_map(stack_attempt, stack_size)
                        stack_addr = stack_attempt
                        stack_mapped = True
                        self.log(f"Stack mapped at 0x{stack_addr:x}")
                        break
                    except Exception:
                        continue

                if not stack_mapped:
                    self.log("Failed to map stack at any location")
                    return None

                if is_64bit:
                    self.mu.reg_write(UC_X86_REG_RSP, stack_addr + stack_size - 8)
                    self.mu.reg_write(UC_X86_REG_RBP, 0)
                else:
                    self.mu.reg_write(UC_X86_REG_ESP, stack_addr + stack_size - 4)
                    self.mu.reg_write(UC_X86_REG_EBP, 0)

            except Exception as e:
                self.log(f"Failed to setup stack: {str(e)}")
                return None

            # Install hooks with enhanced error handling
            try:
                self.mu.hook_add(UC_HOOK_CODE, self.hook_code)
                self.log("Code hook installed")

                try:
                    self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self.hook_mem_read_unmapped)
                    self.mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_write_unmapped)
                    self.mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.hook_mem_fetch_unmapped)
                    try:
                        self.mu.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
                        self.log("All memory access hooks installed successfully")
                    except Exception:
                        self.log("Memory access hooks installed (no invalid hook)")
                except Exception as hook_e:
                    self.log(f"Some memory hooks failed: {str(hook_e)}")

            except Exception as e:
                self.log(f"Failed to install hooks: {str(e)}. Continuing with limited functionality.")

            # Pre-map common memory regions that VMProtect might access (best-effort)
            self.log("Pre-mapping common VMProtect memory regions...")
            common_regions = [
                (0x1000, 0xF000),      # Low memory region
                (0x10000, 0x10000),    # Additional low region
                (0x77000000, 0x1000000), # Common Windows DLL region
                (0x7c800000, 0x800000),  # Another Windows region
            ]

            for base, size in common_regions:
                try:
                    # Skip regions that overlap with our image mapping to avoid conflicts
                    if not (base >= image_base + total_mapped_size or base + size <= image_base):
                        continue
                    self.mu.mem_map(base, size)
                    chunk_size = 0x10000
                    for offset in range(0, size, chunk_size):
                        actual_size = min(chunk_size, size - offset)
                        self.mu.mem_write(base + offset, b'\x00' * actual_size)
                    self.log(f"Pre-mapped region 0x{base:x}-0x{base+size:x}")
                except Exception:
                    # Not critical if pre-mapping fails
                    pass

            # Validate entry point before emulation
            entry_point = self.original_entry_point
            if entry_point < image_base or entry_point >= image_base + image_size:
                self.log(f"[!] Warning: Entry point 0x{entry_point:x} outside image bounds")
                for section in self.pe.sections:
                    sec_name = section.Name.decode(errors='ignore').strip('\x00')
                    if 'vmp' in sec_name.lower() or 'text' in sec_name.lower():
                        alt_entry = image_base + section.VirtualAddress
                        self.log(f"Trying alternative entry point in {sec_name}: 0x{alt_entry:x}")
                        entry_point = alt_entry
                        break

            try:
                entry_bytes = self.mu.mem_read(entry_point, 16)
                self.log(f"Entry point bytes: {entry_bytes.hex()}")

                if entry_bytes[:4] == b'\x00\x00\x00\x00':
                    self.log("[!] Entry point contains null bytes, may be invalid")
                elif entry_bytes[0] in [0xCC, 0xC3]:
                    self.log("[!] Entry point starts with breakpoint or return")

            except Exception as e:
                self.log(f"[!] Cannot read entry point: {str(e)}")
                return None

            # Calculate end address more conservatively
            end_address = image_base + total_mapped_size -1

            self.log(f"Starting enhanced emulation:")
            self.log(f"  Entry Point: 0x{entry_point:x}")
            self.log(f"  End Address: 0x{end_address:x}")
            self.log(f"  Architecture: {'64-bit' if is_64bit else '32-bit'}")
            self.log(f"  Timeout: {timeout}s")
            self.log(f"  Max Instructions: {max_instructions}")

            # Start emulation with enhanced parameters and error recovery
            emulation_attempts = [
                (timeout * 1000000, max_instructions),      # Full timeout
                (10 * 1000000, max_instructions // 2),      # Shorter timeout
                (5 * 1000000, 100000),                      # Very short run
            ]

            emulation_success = False
            for attempt, (timeout_us, max_inst) in enumerate(emulation_attempts):
                try:
                    self.log(f"Emulation attempt {attempt + 1}: timeout={timeout_us//1000000}s, max_inst={max_inst}")
                    self.mu.emu_start(
                        int(entry_point),
                        int(end_address),
                        timeout=int(timeout_us),
                        count=int(max_inst)
                    )
                    emulation_success = True
                    self.log(f"Emulation attempt {attempt + 1} completed successfully")
                    break

                except Exception as e:
                    self.log(f"Emulation attempt {attempt + 1} failed: {str(e)}")

                    if self.instruction_count > 10:
                        emulation_success = True
                        self.log(f"Partial success - executed {self.instruction_count} instructions")
                        break

                    self.instruction_count = 0

                    if attempt == len(emulation_attempts) - 1:
                        self.log("All emulation attempts failed, trying single-step mode")
                        try:
                            for i in range(100):
                                try:
                                    self.mu.emu_start(entry_point + i, entry_point + i + 1, count=1)
                                    self.instruction_count += 1
                                except Exception:
                                    break
                            if self.instruction_count > 0:
                                emulation_success = True
                                self.log(f"Single-step mode executed {self.instruction_count} instructions")
                        except Exception as single_e:
                            self.log(f"Single-step mode also failed: {str(single_e)}")

            if not emulation_success:
                self.log("All emulation attempts failed")

            # Continue with analysis even if emulation had issues
            self.log(f"Emulation completed. Executed {self.instruction_count} instructions.")

            if self.oep:
                self.log(f"SUCCESS: Found OEP at 0x{self.oep:x}")
            elif self.potential_oeps:
                best_oep = max(self.potential_oeps, key=lambda x: x['confidence'])
                self.oep = best_oep['address']
                self.log(f"Selected best OEP candidate: 0x{self.oep:x} (confidence: {best_oep['confidence']}, pattern: {best_oep['pattern']})")
            else:
                self.log("No OEP found during emulation")

            if not self.oep:
                try:
                    self.dump_executed_pages("dumped_pages")
                except Exception as e:
                    self.log(f"[!] Failed to dump executed pages: {e}")

            # Prepare result
            if self.oep or self.vmprotect_data:
                unpacked_path = None
                try:
                    unpacked_data = self.mu.mem_read(image_base, aligned_image_size)
                    # Use a temporary file to avoid passing large data through signals
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin", prefix="unpacked_") as tmp:
                        tmp.write(unpacked_data)
                        unpacked_path = tmp.name
                    self.log(f"Unpacked data saved temporarily to {unpacked_path}")
                except Exception:
                    unpacked_path = None
                    self.log("Failed to read unpacked data from memory")

                result = {
                    "oep": self.oep,
                    "unpacked_data_path": unpacked_path,
                    "original_pe_path": self.file_path,
                    "instruction_count": self.instruction_count,
                    "potential_oeps": self.potential_oeps,
                    "unpacker_sections": list(self.unpacker_sections)
                }

                if self.vmprotect_data:
                    result["vmprotect_data"] = self.vmprotect_data
                    try:
                        decompressed_sections = self.decompress_vmprotect_lzma(self.vmprotect_data)
                        if decompressed_sections:
                            ds_paths = {}
                            with tempfile.TemporaryDirectory() as tmpdir:
                                for rva, data in decompressed_sections.items():
                                    path = os.path.join(tmpdir, f"ds_{rva:x}.bin")
                                    with open(path, "wb") as f:
                                        f.write(data)
                                    ds_paths[rva] = path
                            result["decompressed_section_paths"] = ds_paths
                        else:
                            result["decompressed_sections"] = None
                    except Exception as e:
                        self.log(f"[VMProtect] Decompression exception while building result: {e}")
                        result["decompressed_sections"] = None


                return result
            else:
                self.log("Unpacking failed - no OEP found and no VMProtect data extracted")
                return None

        except Exception as e:
            self.log(f"[!] Critical error during unpacking: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def save_unpacked_file(self, result, output_path):
        """Save the unpacked file with proper PE structure reconstruction"""
        unpacked_data_path = result.get("unpacked_data_path")
        if not unpacked_data_path or not os.path.exists(unpacked_data_path):
            self.log("No unpacked data to save")
            return False

        try:
            with open(unpacked_data_path, "rb") as f:
                unpacked_data = f.read()
            
            original_pe = pefile.PE(result["original_pe_path"])

            # Fix the entry point if OEP was found
            if result.get("oep"):
                oep_rva = result["oep"] - original_pe.OPTIONAL_HEADER.ImageBase
                original_pe.OPTIONAL_HEADER.AddressOfEntryPoint = oep_rva
                self.log(f"Updated entry point to 0x{oep_rva:x}")

            # Reconstruct PE with unpacked data
            pe_data = bytearray(original_pe.write())

            # Update section data with unpacked content
            for section in original_pe.sections:
                if section.VirtualAddress < len(unpacked_data):
                    section_start = section.VirtualAddress
                    section_size = min(section.Misc_VirtualSize, len(unpacked_data) - section_start)

                    if section_size > 0:
                        section_data = unpacked_data[section_start:section_start + section_size]

                        # Update raw data if section has file mapping
                        if section.PointerToRawData > 0:
                            raw_size = min(len(section_data), section.SizeOfRawData)
                            pe_data[section.PointerToRawData:section.PointerToRawData + raw_size] = section_data[:raw_size]

            # Write VMProtect decompressed sections if available
            decompressed_paths = result.get("decompressed_section_paths", {})
            if decompressed_paths:
                for rva, path in decompressed_paths.items():
                    if os.path.exists(path):
                        with open(path, "rb") as f:
                            data = f.read()
                        if rva < len(unpacked_data):
                            for section in original_pe.sections:
                                if (section.VirtualAddress <= rva < 
                                    section.VirtualAddress + section.Misc_VirtualSize):

                                    if section.PointerToRawData > 0:
                                        offset_in_section = rva - section.VirtualAddress
                                        raw_offset = section.PointerToRawData + offset_in_section
                                        data_size = min(len(data), len(pe_data) - raw_offset)

                                        if data_size > 0:
                                            pe_data[raw_offset:raw_offset + data_size] = data[:data_size]
                                            self.log(f"Applied VMProtect decompressed data to section at RVA 0x{rva:x}")
                                    break

            # Save the reconstructed PE file
            with open(output_path, 'wb') as f:
                f.write(pe_data)

            self.log(f"Unpacked file saved to: {output_path}")

            if result.get("oep"):
                self.log(f"New entry point: 0x{result['oep']:x}")
            if result.get("instruction_count"):
                self.log(f"Instructions executed: {result['instruction_count']}")
            if decompressed_paths:
                self.log(f"VMProtect sections decompressed: {len(decompressed_paths)}")

            return True

        except Exception as e:
            self.log(f"Failed to save unpacked file: {str(e)}")
            return False
        finally:
            # Clean up temporary file
            if os.path.exists(unpacked_data_path):
                try:
                    os.remove(unpacked_data_path)
                except OSError:
                    pass

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

def run_capa_analysis(file_path: str, capa_exe_path: str = "capa.exe", **kwargs) -> Optional[str]:
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

# --- Graph Visualization Classes ---

class Arrow(QGraphicsLineItem):
    """A QGraphicsLineItem with an arrowhead."""
    def __init__(self, source_point, dest_point, parent=None):
        super().__init__(source_point.x(), source_point.y(), dest_point.x(), dest_point.y(), parent)
        self.arrow_size = 10

    def paint(self, painter, option, widget=None):
        # Draw the line
        painter.setPen(self.pen())
        painter.drawLine(self.line())

        # Draw the arrowhead
        angle = math.atan2(-self.line().dy(), self.line().dx())
        arrow_p1 = self.line().p2() - QPointF(math.sin(angle + math.pi / 3) * self.arrow_size,
                                             math.cos(angle + math.pi / 3) * self.arrow_size)
        arrow_p2 = self.line().p2() - QPointF(math.sin(angle + math.pi - math.pi / 3) * self.arrow_size,
                                             math.cos(angle + math.pi - math.pi / 3) * self.arrow_size)
        
        arrow_head = QPolygonF([self.line().p2(), arrow_p1, arrow_p2])
        painter.setBrush(self.pen().color())
        painter.drawPolygon(arrow_head)

class GraphNode(QGraphicsItem):
    """A movable node for the function call graph."""
    def __init__(self, name, node_type='dll', full_name=None):
        super().__init__()
        self.name = name
        self.node_type = node_type
        self.full_name = full_name or name
        self.edges = []
        self.setFlag(QGraphicsItem.ItemIsMovable)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges)
        self.setCacheMode(QGraphicsItem.DeviceCoordinateCache)
        self.setZValue(1)
        self.setToolTip(self.full_name)

    def boundingRect(self):
        # Adjust size based on node type for better visualization
        if self.node_type == 'function':
            return QtCore.QRectF(-60, -15, 120, 30)
        return QtCore.QRectF(-75, -20, 150, 40)

    def paint(self, painter, option, widget):
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.boundingRect()
        
        # Color coding based on node type
        if self.node_type == 'exe':
            brush_color = QColor("#007ACC") # Blue
            pen_color = QColor("#FFFFFF")
        elif self.node_type == 'dll':
            brush_color = QColor("#3E3E42") # Dark Grey
            pen_color = QColor("#CCCCCC")
        else: # function
            brush_color = QColor("#6A9955") # Green
            pen_color = QColor("#FFFFFF")
            
        painter.setBrush(brush_color)
        painter.setPen(QPen(pen_color, 2))
        painter.drawRoundedRect(rect, 10, 10)
        
        painter.setPen(pen_color)
        painter.drawText(rect, Qt.AlignCenter, self.name)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for edge in self.edges:
                edge.adjust()
        return super().itemChange(change, value)

class GraphEdge(QGraphicsItem):
    """An edge connecting two nodes in the graph."""
    def __init__(self, source, dest):
        super().__init__()
        self.source = source
        self.dest = dest
        self.source.edges.append(self)
        self.dest.edges.append(self)
        self.adjust()
        self.setZValue(0)

    def boundingRect(self):
        return self.path.boundingRect() if hasattr(self, 'path') else QtCore.QRectF()

    def paint(self, painter, option, widget):
        if not self.source or not self.dest:
            return
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(QColor("#888888"), 1.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPath(self.path)

    def adjust(self):
        if not self.source or not self.dest:
            return
        self.prepareGeometryChange()
        
        line = QtCore.QLineF(self.mapFromItem(self.source, 0, 0), self.mapFromItem(self.dest, 0, 0))
        self.path = QPainterPath()
        self.path.moveTo(line.p1())
        self.path.lineTo(line.p2())

# --- Main Application Window ---

class OpenHydraFileAnalyzer(QtWidgets.QMainWindow):
    """The main window for the OpenHydraFileAnalyzer application."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setWindowIcon(self.style().standardIcon(QtWidgets.QStyle.SP_ComputerIcon))
        self.resize(1800, 1200)

        # --- Thread Pool ---
        self.threadpool = QThreadPool()
        self.threadpool.setMaxThreadCount(128)
        logging.info("Multithreading with maximum %d threads" % self.threadpool.maxThreadCount())
        
        # --- Task Management ---
        self.task_counter = 0

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
        
        self.unpacker_result_a: Optional[Dict] = None
        self.unpacker_result_b: Optional[Dict] = None


        self.matches_a: List[Dict] = []
        self.matches_b: List[Dict] = []
        self.capa_matches: List[Tuple[str, Dict]] = []
        self.diff_hunks: List[Dict] = []
        self.yara_index: Dict = {}
        self._yara_keys: List = []

        self.match_idx_a: int = -1
        self.match_idx_b: int = -1
        
        self.show_diff: bool = True
        self.context: int = self.settings.get("context", DEFAULT_CONTEXT_SIZE)
        
        self.pe_extractor = PEFeatureExtractor()
        
        self.graph_view_mode = "unified"
        self.graph_nodes = {}
        
        self.current_center_offset = 0

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
        self.save_settings()
        super().closeEvent(event)

    # --- UI Building ---
    def _build_ui(self):
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)
        self.outer_layout = QtWidgets.QVBoxLayout(self.central_widget)

        self._create_toolbar()
        self._create_main_layout()
        self._create_status_bar()

    def _create_toolbar(self):
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
        main_split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.outer_layout.addWidget(main_split, stretch=1)

        left_pane = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_pane)
        main_split.addWidget(left_pane)
        left_pane.setMinimumWidth(450)

        self.main_tabs = QtWidgets.QTabWidget()
        self.main_tabs.currentChanged.connect(self.on_main_tab_changed)
        left_layout.addWidget(self.main_tabs, stretch=1)

        # --- Tabs on the Left ---
        self._create_results_tab(self.main_tabs)
        self._create_pe_analysis_tab(self.main_tabs)
        self._create_roadmap_tab(self.main_tabs)
        self._create_call_view_tab(self.main_tabs)
        self._create_assembly_roadmap_tab(self.main_tabs)
        self._create_unpacker_tab(self.main_tabs)
        self._create_die_tab(self.main_tabs)
        self._create_editors_tab(self.main_tabs)
        self._create_yargen_gui_tab(self.main_tabs)
        self._create_clamav_gui_tab(self.main_tabs)
        self._create_base64_tool_tab(self.main_tabs)
        self._create_excluded_rules_tab(self.main_tabs)
        self._create_task_manager_tab(self.main_tabs)

        left_layout.addWidget(QtWidgets.QLabel("<b>Selection Details</b>"))
        self.details = QtWidgets.QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(160)
        left_layout.addWidget(self.details)

        # --- Right Pane (Unified View) ---
        right_pane = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_pane)
        main_split.addWidget(right_pane)

        self._create_unified_views(right_layout)
        
        main_split.setSizes([500, 1300])

    def _create_results_tab(self, parent_tabs):
        results_widget = QtWidgets.QWidget()
        results_layout = QtWidgets.QVBoxLayout(results_widget)
        parent_tabs.addTab(results_widget, "Scan Results")

        self.search_results_edit = QtWidgets.QLineEdit()
        self.search_results_edit.setPlaceholderText("Search results...")
        self.search_results_edit.textChanged.connect(self.filter_results)
        results_layout.addWidget(self.search_results_edit)

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

    def _create_pe_analysis_tab(self, parent_tabs):
        pe_widget = QtWidgets.QWidget()
        pe_layout = QtWidgets.QVBoxLayout(pe_widget)
        parent_tabs.addTab(pe_widget, "PE Analysis")

        pe_toolbar = QtWidgets.QHBoxLayout()
        self.pe_file_selector = QtWidgets.QComboBox()
        self.pe_file_selector.addItems(["File A", "File B"])
        self.pe_file_selector.currentTextChanged.connect(self.display_pe_features)
        pe_toolbar.addWidget(QtWidgets.QLabel("Target:"))
        pe_toolbar.addWidget(self.pe_file_selector)
        
        self.btn_generate_yara = QtWidgets.QPushButton("Generate Rule with yarGen")
        self.btn_generate_yara.clicked.connect(self.prepare_yargen_for_current_file)
        self.btn_generate_yara.setEnabled(False)
        pe_toolbar.addWidget(self.btn_generate_yara)
        pe_toolbar.addStretch()
        pe_layout.addLayout(pe_toolbar)
        
        self.search_pe_edit = QtWidgets.QLineEdit()
        self.search_pe_edit.setPlaceholderText("Search PE info...")
        self.search_pe_edit.textChanged.connect(self.filter_pe_analysis)
        pe_layout.addWidget(self.search_pe_edit)

        pe_analysis_tabs = QtWidgets.QTabWidget()
        pe_layout.addWidget(pe_analysis_tabs)

        self.pe_features_output = QtWidgets.QTextEdit()
        self.pe_features_output.setReadOnly(True)
        self.pe_features_output.setFont(QtGui.QFont("Consolas", 10))
        pe_analysis_tabs.addTab(self.pe_features_output, "Extracted Features")

        self.resource_tree = QtWidgets.QTreeWidget()
        self.resource_tree.setHeaderLabels(["Type", "ID/Name", "Language", "Size", "Offset"])
        self.resource_tree.setColumnWidth(0, 150)
        pe_analysis_tabs.addTab(self.resource_tree, "Resource Viewer")

    def _create_roadmap_tab(self, parent_tabs):
        roadmap_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(roadmap_widget)
        parent_tabs.addTab(roadmap_widget, "File Roadmap")

        self.roadmap_scene = QGraphicsScene()
        self.roadmap_view = ZoomableView(self.roadmap_scene)
        layout.addWidget(self.roadmap_view)

    def _create_call_view_tab(self, parent_tabs):
        call_view_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(call_view_widget)
        parent_tabs.addTab(call_view_widget, "Call View")

        self.search_call_view_edit = QtWidgets.QLineEdit()
        self.search_call_view_edit.setPlaceholderText("Search imports...")
        self.search_call_view_edit.textChanged.connect(self.filter_call_view)
        layout.addWidget(self.search_call_view_edit)

        self.call_view_tree = QtWidgets.QTreeWidget()
        self.call_view_tree.setHeaderLabels(["DLL / Function", "Address"])
        self.call_view_tree.itemClicked.connect(self.on_call_view_item_selected)
        layout.addWidget(self.call_view_tree)

    def _create_assembly_roadmap_tab(self, parent_tabs):
        asm_roadmap_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(asm_roadmap_widget)
        parent_tabs.addTab(asm_roadmap_widget, "Assembly Roadmap")

        self.asm_roadmap_scene = QGraphicsScene()
        self.asm_roadmap_view = ZoomableView(self.asm_roadmap_scene)
        layout.addWidget(self.asm_roadmap_view)

    def _create_unpacker_tab(self, parent_tabs):
        unpacker_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(unpacker_widget)
        parent_tabs.addTab(unpacker_widget, "Unpacker")

        toolbar = QtWidgets.QHBoxLayout()
        btn_unpack_a = QtWidgets.QPushButton("Unpack File A")
        btn_unpack_a.clicked.connect(lambda: self.run_unpacker('A'))
        toolbar.addWidget(btn_unpack_a)
        
        btn_unpack_b = QtWidgets.QPushButton("Unpack File B")
        btn_unpack_b.clicked.connect(lambda: self.run_unpacker('B'))
        toolbar.addWidget(btn_unpack_b)

        self.btn_save_unpacked_a = QtWidgets.QPushButton("Save Unpacked A")
        self.btn_save_unpacked_a.clicked.connect(lambda: self.save_unpacked_file_dialog('A'))
        self.btn_save_unpacked_a.setEnabled(False)
        toolbar.addWidget(self.btn_save_unpacked_a)
        
        self.btn_save_unpacked_b = QtWidgets.QPushButton("Save Unpacked B")
        self.btn_save_unpacked_b.clicked.connect(lambda: self.save_unpacked_file_dialog('B'))
        self.btn_save_unpacked_b.setEnabled(False)
        toolbar.addWidget(self.btn_save_unpacked_b)
        
        layout.addLayout(toolbar)

        self.unpacker_console = QtWidgets.QPlainTextEdit()
        self.unpacker_console.setReadOnly(True)
        self.unpacker_console.setFont(QtGui.QFont("Consolas", 10))
        layout.addWidget(self.unpacker_console)

    def _create_die_tab(self, parent_tabs):
        self.die_output = QtWidgets.QPlainTextEdit()
        self.die_output.setReadOnly(True)
        self.die_output.setFont(QtGui.QFont("Consolas", 10))
        parent_tabs.addTab(self.die_output, "DetectItEasy")
        
    def _create_editors_tab(self, parent_tabs):
        editors_widget = QtWidgets.QWidget()
        editors_layout = QtWidgets.QVBoxLayout(editors_widget)
        parent_tabs.addTab(editors_widget, "Editors")
        
        self.search_editor_edit = QtWidgets.QLineEdit()
        self.search_editor_edit.setPlaceholderText("Search in editor...")
        self.search_editor_edit.textChanged.connect(self.filter_editors)
        editors_layout.addWidget(self.search_editor_edit)

        editor_tabs = QtWidgets.QTabWidget()
        editors_layout.addWidget(editor_tabs)

        yara_editor_widget = self._create_editor_tab_content(self.save_yara_from_editor, self.validate_yara_editor)
        self.yara_editor = yara_editor_widget.findChild(QtWidgets.QTextEdit)
        self.yara_highlighter = YaraHighlighter(self.yara_editor.document())
        editor_tabs.addTab(yara_editor_widget, "YARA Editor")
        
        capa_editor_widget = self._create_editor_tab_content()
        self.capa_editor = capa_editor_widget.findChild(QtWidgets.QTextEdit)
        self.capa_highlighter = CapaHighlighter(self.capa_editor.document())
        editor_tabs.addTab(capa_editor_widget, "CAPA Editor")

    def _create_editor_tab_content(self, save_func=None, validate_func=None):
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
        self.yargen_widget = QtWidgets.QWidget()
        yargen_layout = QtWidgets.QVBoxLayout(self.yargen_widget)
        
        form_layout = QtWidgets.QFormLayout()
        
        self.yargen_malware_path = QtWidgets.QLineEdit()
        self.yargen_output_file = QtWidgets.QLineEdit()
        self.yargen_author = QtWidgets.QLineEdit("Emirhan Ucan & Hacimurad")
        self.yargen_reference = QtWidgets.QLineEdit("VirusShare, VirusTotal, etc.")
        
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
        self.clamav_widget = QtWidgets.QWidget()
        clamav_layout = QtWidgets.QVBoxLayout(self.clamav_widget)
        
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
        self.clamav_command_select.addItems(["Info (--info)", "List Signatures (--list-sigs)", "Unpack (--unpack)", "Find Signatures (--find-sigs)"])
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

        clamav_layout.addWidget(QtWidgets.QLabel("<b>SigTool Output</b>"))
        self.clamav_console = QtWidgets.QPlainTextEdit()
        self.clamav_console.setReadOnly(True)
        self.clamav_console.setFont(QtGui.QFont("Consolas", 10))
        clamav_layout.addWidget(self.clamav_console)
        
        tabs.addTab(self.clamav_widget, "ClamAV SigTool")

    def _create_base64_tool_tab(self, tabs):
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)
        
        layout.addWidget(QtWidgets.QLabel("<b>Input</b>"))
        self.base64_input = QtWidgets.QTextEdit()
        self.base64_input.setPlaceholderText("Enter text or hex string to encode/decode")
        self.base64_input.setFont(QtGui.QFont("Consolas", 10))
        layout.addWidget(self.base64_input)
        
        controls_layout = QtWidgets.QHBoxLayout()
        self.base64_mode = QtWidgets.QComboBox()
        self.base64_mode.addItems(["Text", "Hex"])
        controls_layout.addWidget(self.base64_mode)
        
        btn_encode = QtWidgets.QPushButton("Encode")
        btn_encode.clicked.connect(self.run_base64_encode)
        controls_layout.addWidget(btn_encode)
        
        btn_decode = QtWidgets.QPushButton("Decode")
        btn_decode.clicked.connect(self.run_base64_decode)
        controls_layout.addWidget(btn_decode)
        layout.addLayout(controls_layout)
        
        layout.addWidget(QtWidgets.QLabel("<b>Output</b>"))
        self.base64_output = QtWidgets.QTextEdit()
        self.base64_output.setReadOnly(True)
        self.base64_output.setFont(QtGui.QFont("Consolas", 10))
        layout.addWidget(self.base64_output)
        
        tabs.addTab(widget, "Base64")

    def _create_excluded_rules_tab(self, tabs):
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

    def _create_task_manager_tab(self, tabs):
        task_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(task_widget)
        
        self.task_table = QtWidgets.QTableWidget()
        self.task_table.setColumnCount(3)
        self.task_table.setHorizontalHeaderLabels(["ID", "Task", "Status"])
        self.task_table.horizontalHeader().setStretchLastSection(True)
        self.task_table.setColumnWidth(0, 40)
        self.task_table.setColumnWidth(1, 250)
        
        layout.addWidget(self.task_table)
        tabs.addTab(task_widget, "Task Manager")
        
    def _create_unified_views(self, parent_layout):
        controls = QtWidgets.QHBoxLayout()
        controls.addWidget(QtWidgets.QLabel("Context:"))
        self.spin_context = QtWidgets.QSpinBox()
        self.spin_context.setRange(MIN_CONTEXT_SIZE, MAX_CONTEXT_SIZE)
        self.spin_context.setValue(self.context)
        self.spin_context.valueChanged.connect(self.on_context_change)
        controls.addWidget(self.spin_context)
        controls.addStretch()
        parent_layout.addLayout(controls)

        view_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        
        self.unified_view_a = QtWidgets.QTextEdit()
        self.unified_view_b = QtWidgets.QTextEdit()

        view_splitter.addWidget(self._create_view_pane("File A - Unified View", self.unified_view_a))
        view_splitter.addWidget(self._create_view_pane("File B - Unified View", self.unified_view_b))
        
        for view in (self.unified_view_a, self.unified_view_b):
            view.setReadOnly(True)
            view.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
            font = QtGui.QFont("Consolas" if sys.platform == "win32" else "DejaVu Sans Mono", 11)
            view.setFont(font)
            view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
            view.customContextMenuRequested.connect(self.on_hex_context_menu)

        parent_layout.addWidget(view_splitter, stretch=1)

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

    def _create_view_pane(self, title, widget):
        pane = QtWidgets.QGroupBox(title)
        layout = QtWidgets.QVBoxLayout(pane)
        layout.setContentsMargins(2, 8, 2, 2)
        layout.addWidget(widget)
        return pane

    def _create_status_bar(self):
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
                QMainWindow, QWidget { background-color: #F0F0F0; color: #000000; }
                QTextEdit, QPlainTextEdit, QTreeWidget, QGraphicsView { background-color: #FFFFFF; color: #000000; border: 1px solid #CCCCCC; }
                QListWidget { background-color: #FFFFFF; color: #000000; border: 1px solid #CCCCCC; }
                QTableWidget { background-color: #FFFFFF; color: #000000; border: 1px solid #CCCCCC; gridline-color: #DDDDDD; }
                QTableWidget::item { padding: 3px; }
                QHeaderView::section { background-color: #F0F0F0; padding: 4px; border: 1px solid #CCCCCC; }
                QPushButton { background-color: #E1E1E1; color: #000000; border: 1px solid #ADADAD; padding: 5px; border-radius: 2px; }
                QPushButton:hover { background-color: #E5F1FB; border: 1px solid #0078D7; }
                QPushButton:pressed { background-color: #CCE4F7; }
                QLabel, QGroupBox { color: #000000; }
                QGroupBox { border: 1px solid #CCCCCC; margin-top: 0.5em; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px 0 3px; }
                QLineEdit, QSpinBox, QComboBox { background-color: #FFFFFF; color: #000000; border: 1px solid #ADADAD; padding: 2px; }
                QTabWidget::pane { border: 1px solid #CCCCCC; }
                QTabBar::tab { background: #E1E1E1; color: #000000; padding: 8px; }
                QTabBar::tab:selected { background: #FFFFFF; }
                QSplitter::handle { background: #CCCCCC; }
            """

    def get_dark_theme_style(self):
        return """
            QMainWindow, QWidget { background-color: #2D2D30; color: #F1F1F1; }
            QTextEdit, QPlainTextEdit, QTreeWidget, QGraphicsView { background-color: #1E1E1E; color: #D4D4D4; border: 1px solid #3E3E42; }
            QListWidget { background-color: #252526; color: #CCCCCC; border: 1px solid #3E3E42; }
            QTableWidget { background-color: #252526; color: #CCCCCC; border: 1px solid #3E3E42; gridline-color: #3E3E42; }
            QTableWidget::item { padding: 3px; }
            QHeaderView::section { background-color: #3E3E42; padding: 4px; border: 1px solid #555555; }
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
                self.matches_a = []
            else:
                self.file_b_path = path
                self.file_b_data = bytearray(data)
                self.pe_features_b = None
                self.matches_b = []
            
            self.diff_hunks = [] 
            self.capa_matches = [m for m in self.capa_matches if m[0] != which]
            self._build_yara_index()

            self.lbl_status.setText(f"Loaded {which}: {os.path.basename(path)} ({len(data)} bytes)")
            
            # Run feature extraction automatically for call graph
            self.run_pe_feature_extraction(which=which, silent=True)
            self._refresh_lists_and_views()
            self.render_region(center=0)
            self.update_roadmap()


        except Exception as e:
            msg = f"Error loading File {which}: {e}"
            logging.error(msg, exc_info=True)
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
            error_message = f"YARA Compile Error:\n\n{e}"
            QtWidgets.QMessageBox.critical(self, "YARA Compile Error", error_message)
        except Exception as e:
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
        if output_file: command.extend(["-o", output_file])
            
        author = self.yargen_author.text()
        if author: command.extend(["-a", author])
            
        reference = self.yargen_reference.text()
        if reference: command.extend(["-r", reference])

        if self.yargen_opcodes.isChecked(): command.append("--opcodes")
        if self.yargen_meaningful.isChecked(): command.append("--meaningful-words-only")
        if self.yargen_excludegood.isChecked(): command.append("--excludegood")
        if self.yargen_nofilesize.isChecked(): command.append("--nofilesize")
        if self.yargen_nosimple.isChecked(): command.append("--nosimple")

        self.run_generic_subprocess(command, self.yargen_console, "Run yarGen")

    def update_yargen_db(self):
        yar_gen_path = os.path.join(script_dir, "yarGen.py")
        if not os.path.exists(yar_gen_path):
            QtWidgets.QMessageBox.warning(self, "yarGen Not Found", "Could not find yarGen.py in the script directory.")
            return
        command = [sys.executable, yar_gen_path, "--update"]
        self.run_generic_subprocess(command, self.yargen_console, "Update yarGen DB")

    def run_generic_subprocess(self, command, output_widget, task_name, stdin_data=None):
        output_widget.clear()
        task_id = self.add_task_to_manager(task_name)

        def task(progress_callback, console_output_callback):
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
                console_output_callback.emit(stdout_data.strip())
            else:
                for output in iter(process.stdout.readline, ''):
                    console_output_callback.emit(output.strip())
            
            return process.wait()

        worker = Worker(task)
        worker.signals.console_output.connect(output_widget.appendPlainText)
        worker.signals.result.connect(lambda code: self.update_task_in_manager(task_id, f"Finished with exit code {code}."))
        worker.signals.error.connect(lambda err: self.update_task_in_manager(task_id, f"Error: {err[1]}"))
        self.threadpool.start(worker)

    # --- Analysis and Scanning ---
    def scan_yara_only(self):
        if not self.yara_path:
            QtWidgets.QMessageBox.warning(self, "No YARA", "Load a YARA rule file first.")
            return
        
        task_id = self.add_task_to_manager("YARA Scan")
        
        def task(progress_callback, console_output_callback):
            matches_a = collect_yara_matches(self.yara_path, bytes(self.file_a_data), self.excluded_rules) if self.file_a_data else []
            matches_b = collect_yara_matches(self.yara_path, bytes(self.file_b_data), self.excluded_rules) if self.file_b_data else []
            return {"matches_a": matches_a, "matches_b": matches_b}

        worker = Worker(task)
        worker.signals.result.connect(lambda result: self.on_yara_scan_finished(result, task_id))
        worker.signals.error.connect(lambda err: self.update_task_in_manager(task_id, f"Error: {err[1]}"))
        self.threadpool.start(worker)

    def on_yara_scan_finished(self, result, task_id):
        self.matches_a = result["matches_a"]
        self.matches_b = result["matches_b"]
        self.diff_hunks = []
        self._build_yara_index()
        self._refresh_lists_and_views()
        self.update_task_in_manager(task_id, "Complete")

    def scan_yara_and_diff(self):
        if self.file_a_data is None or self.file_b_data is None:
            QtWidgets.QMessageBox.warning(self, "Missing Files", "Load both File A and File B to run a diff.")
            return

        task_id = self.add_task_to_manager("YARA Scan + Diff")

        def task(progress_callback, console_output_callback):
            matches_a = collect_yara_matches(self.yara_path, bytes(self.file_a_data), self.excluded_rules) if self.yara_path else []
            matches_b = collect_yara_matches(self.yara_path, bytes(self.file_b_data), self.excluded_rules) if self.yara_path else []
            diff_hunks = compute_diff_hunks(bytes(self.file_a_data), bytes(self.file_b_data))
            return {"matches_a": matches_a, "matches_b": matches_b, "diff_hunks": diff_hunks}
        
        worker = Worker(task)
        worker.signals.result.connect(lambda result: self.on_yara_diff_finished(result, task_id))
        worker.signals.error.connect(lambda err: self.update_task_in_manager(task_id, f"Error: {err[1]}"))
        self.threadpool.start(worker)

    def on_yara_diff_finished(self, result, task_id):
        self.matches_a = result["matches_a"]
        self.matches_b = result["matches_b"]
        self.diff_hunks = result["diff_hunks"]
        self._build_yara_index()
        self._refresh_lists_and_views()
        self.update_task_in_manager(task_id, "Complete")

    def _build_yara_index(self):
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
        center = 0
        current_row = self.yara_list.currentRow()
        if current_row >= 0 and current_row < len(self._yara_keys):
            key = self._yara_keys[current_row]
            offs = self.yara_index.get(key, {})
            a_offs = offs.get('a_offsets', [])
            b_offs = offs.get('b_offsets', [])
            if a_offs:
                center = a_offs[0]
            elif b_offs:
                center = b_offs[0]
        else:
            current_row = self.hunk_list.currentRow()
            if current_row >= 0 and current_row < len(self.diff_hunks):
                center = self.diff_hunks[current_row]['start']
        
        self.current_center_offset = center
        self.render_region(center=center)
        
        # Update only the currently visible tab
        self.on_main_tab_changed(self.main_tabs.currentIndex())

    def render_region(self, center=0, yara_key=None):
        self.current_center_offset = center
        ctx = self.context
        start = max(0, center - ctx // 2)
        
        self.unified_view_a.setHtml(self._render_unified_html(True, start, yara_key))
        self.unified_view_b.setHtml(self._render_unified_html(False, start, yara_key))

    def _render_unified_html(self, is_left: bool, start: int, yara_key=None) -> str:
        data = self.file_a_data if is_left else self.file_b_data
        if data is None: return ""

        other_data = self.file_b_data if is_left else self.file_a_data
        matches = self.matches_a if is_left else self.matches_b
        yara_intervals = intervals_from_matches(matches)
        
        selected_yara_intervals = []
        if yara_key:
            for m in matches:
                if (m['rule_name'], m['identifier']) == yara_key:
                    offset = m.get("offset", 0)
                    length = m.get("length", 0)
                    selected_yara_intervals.append((offset, offset + length - 1))

        # Theme colors
        bg_color = "#1E1E1E" if self.is_dark_theme else "#FFFFFF"
        text_color = "#D4D4D4" if self.is_dark_theme else "#000000"
        addr_color = "#6E6E6E" if self.is_dark_theme else "#888888"
        hex_color = "#9CDCFE" if self.is_dark_theme else "#0000FF"
        asm_color = "#DCDCAA" if self.is_dark_theme else "#8B008B"
        comment_color = "#6A9955" if self.is_dark_theme else "#228B22"
        diff_bg = "#5A3800" if self.is_dark_theme else "#FFF2B2"
        yar_bg = "#8B0000" if self.is_dark_theme else "#FFC0CB"
        yar_sel_bg = "#B22222" if self.is_dark_theme else "#FFA07A"
        border_color = "#3E3E42" if self.is_dark_theme else "#CCCCCC"

        css = f"""
        <style>
            body {{ background-color: {bg_color}; color: {text_color}; font-family: Consolas, 'DejaVu Sans Mono', monospace; font-size: 11px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            td {{ vertical-align: top; padding: 0 5px; }}
            .hex-pane {{ width: 55%; border-right: 1px solid {border_color}; }}
            .asm-pane {{ width: 45%; }}
            .addr {{ color: {addr_color}; }}
            .hex {{ color: {hex_color}; }}
            .asm {{ color: {asm_color}; }}
            .comment {{ color: {comment_color}; }}
            .diff {{ background-color: {diff_bg}; }}
            .yar {{ background-color: {yar_bg}; }}
            .yarsel {{ background-color: {yar_sel_bg}; font-weight: bold;}}
        </style>
        """
        html = ["<html><head>", css, "</head><body><pre><table>"]
        
        end = min(start + self.context, len(data))
        pos = start

        cs = None
        if CAPSTONE_AVAILABLE:
            try:
                cs = Cs(CS_ARCH_X86, CS_MODE_64)
                cs.detail = True
            except Exception as e:
                logging.error(f"Capstone init error: {e}")
                cs = None

        while pos < end:
            # --- Hex Pane ---
            hex_pane_html = []
            row_bytes = data[pos:pos+BYTES_PER_ROW]
            if not row_bytes: break

            hex_parts, ascii_parts = [], []
            for j, byte_val in enumerate(row_bytes):
                current_offset = pos + j
                char = chr(byte_val) if 32 <= byte_val <= 126 else '.'
                
                classes = []
                if self.show_diff and other_data and (current_offset >= len(other_data) or other_data[current_offset] != byte_val):
                    classes.append("diff")
                if interval_contains(selected_yara_intervals, current_offset):
                    classes.append("yarsel")
                elif interval_contains(yara_intervals, current_offset):
                    classes.append("yar")
                
                class_attr = f' class="{" ".join(classes)}"' if classes else ""
                hex_parts.append(f"<span{class_attr}>{byte_val:02X}</span>")
                ascii_parts.append(f"<span{class_attr}>{char.replace('&', '&amp;').replace('<', '&lt;')}</span>")
            
            hex_str = " ".join(hex_parts)
            ascii_str = "".join(ascii_parts)
            hex_pane_html.append(f"<span class='addr'>0x{pos:08X}:</span> <span class='hex'>{hex_str:<{BYTES_PER_ROW*3-1}}</span>  |{ascii_str}|")

            # --- Assembly Pane ---
            asm_pane_html = []
            insn = None
            if cs:
                chunk = bytes(data[pos:pos + 16]) # Disassemble from current line
                if chunk:
                    try:
                        insn = next(cs.disasm(chunk, pos), None)
                    except Exception:
                        insn = None

            if insn and insn.address == pos:
                 asm_pane_html.append(f"<span class='asm'>{insn.mnemonic:<10} {insn.op_str}</span>")
                 bytes_consumed = insn.size
            else:
                 asm_pane_html.append("&nbsp;") # Empty line if no instruction starts here
                 bytes_consumed = BYTES_PER_ROW

            # --- Combine into table row ---
            html.append("<tr>")
            html.append(f"<td class='hex-pane'>{'<br>'.join(hex_pane_html)}</td>")
            html.append(f"<td class='asm-pane'>{'<br>'.join(asm_pane_html)}</td>")
            html.append("</tr>")
            
            pos += BYTES_PER_ROW

        html.extend(["</table></pre></body></html>"])
        return "\n".join(html)

    def update_roadmap(self):
        self.roadmap_scene.clear()
        data = self.file_a_data # For now, roadmap is only for File A
        if not data:
            return

        file_size = len(data)
        view_width = self.roadmap_view.width() - 20 # Leave some margin
        
        # Determine block size and layout
        if file_size == 0: return
        block_size = max(1, file_size // 10000) # Aim for around 10k blocks
        blocks_per_row = 64
        
        num_blocks = math.ceil(file_size / block_size)
        num_rows = math.ceil(num_blocks / blocks_per_row)
        
        rect_width = view_width / blocks_per_row
        rect_height = rect_width
        
        self.roadmap_scene.setSceneRect(0, 0, view_width, num_rows * rect_height)

        # Draw blocks
        for i in range(num_blocks):
            row = i // blocks_per_row
            col = i % blocks_per_row
            
            offset = i * block_size
            chunk = data[offset:offset+block_size]
            if not chunk: continue

            entropy = self.pe_extractor._calculate_entropy(chunk)
            color_val = int(entropy * 32) # Scale entropy 0-8 to 0-255
            color = QColor(color_val, color_val, color_val)

            rect = QGraphicsRectItem(col * rect_width, row * rect_height, rect_width, rect_height)
            rect.setBrush(QBrush(color))
            rect.setPen(QPen(QtCore.Qt.NoPen))
            rect.setToolTip(f"Offset: 0x{offset:X}\nEntropy: {entropy:.2f}")
            self.roadmap_scene.addItem(rect)

        # Draw PE section overlays if available
        if self.pe_features_a and 'sections' in self.pe_features_a:
            section_colors = [QColor(255,0,0,50), QColor(0,255,0,50), QColor(0,0,255,50), QColor(255,255,0,50)]
            for i, section in enumerate(self.pe_features_a['sections']):
                offset = section.get('pointer_to_raw_data', 0)
                size = section.get('raw_size', 0)
                name = section.get('name', '')

                start_block = offset // block_size
                end_block = (offset + size) // block_size
                
                start_row = start_block // blocks_per_row
                start_col = start_block % blocks_per_row
                end_row = end_block // blocks_per_row
                end_col = end_block % blocks_per_row
                
                color = section_colors[i % len(section_colors)]
                
                # Draw rect covering the section
                for r in range(start_row, end_row + 1):
                    c_start = start_col if r == start_row else 0
                    c_end = end_col if r == end_row else blocks_per_row - 1
                    
                    x = c_start * rect_width
                    y = r * rect_height
                    w = (c_end - c_start + 1) * rect_width
                    h = rect_height
                    
                    sec_rect = QGraphicsRectItem(x, y, w, h)
                    sec_rect.setBrush(QBrush(color))
                    sec_rect.setPen(QPen(QtCore.Qt.NoPen))
                    sec_rect.setToolTip(f"Section: {name}\nOffset: 0x{offset:X}\nSize: {size}")
                    self.roadmap_scene.addItem(sec_rect)

    def update_call_view(self):
        self.call_view_tree.clear()
        features = self.pe_features_a
        if not features or 'imports' not in features:
            return

        for dll_import in features['imports']:
            dll_name = dll_import.get('dll_name')
            if not dll_name: continue
            
            dll_item = QtWidgets.QTreeWidgetItem([dll_name])
            self.call_view_tree.addTopLevelItem(dll_item)

            for func_import in dll_import.get('imports', []):
                func_name = func_import.get('name')
                if not func_name: continue
                
                address = func_import.get('address', 0)
                func_item = QtWidgets.QTreeWidgetItem([func_name, f"0x{address:X}"])
                dll_item.addChild(func_item)

    def on_call_view_item_selected(self, item, column):
        if item.childCount() == 0: # It's a function
            address_str = item.text(1)
            try:
                address = int(address_str, 16)
                self.render_region(center=address)
                self.details.setPlainText(f"Function: {item.text(0)}\nAddress: {address_str}")
            except ValueError:
                pass

    def filter_call_view(self, text):
        """Filter the call view tree."""
        iterator = QtWidgets.QTreeWidgetItemIterator(self.call_view_tree)
        while iterator.value():
            item = iterator.value()
            match = any(text.lower() in item.text(col).lower() for col in range(item.columnCount()))
            item.setHidden(not match)
            # If a child matches, show its parent
            if match and item.parent():
                item.parent().setHidden(False)
            iterator += 1

    def update_assembly_roadmap(self):
        self.asm_roadmap_scene.clear()
        data = self.file_a_data
        if not (data and CAPSTONE_AVAILABLE):
            self.asm_roadmap_scene.addText("Load a file to view Assembly Roadmap.")
            return

        start_offset = max(0, self.current_center_offset - self.context // 2)
        end_offset = min(start_offset + self.context, len(data))
        code = bytes(data[start_offset:end_offset])
        
        if not code:
            self.asm_roadmap_scene.addText("No data in current view.")
            return

        try:
            cs = Cs(CS_ARCH_X86, CS_MODE_64)
            cs.detail = True
            instructions = list(cs.disasm(code, start_offset))
        except Exception as e:
            self.asm_roadmap_scene.addText(f"Capstone Error: {e}")
            return

        if not instructions:
            self.asm_roadmap_scene.addText("No instructions disassembled in the current view.")
            return

        # 1. Find basic block boundaries
        boundaries = {instructions[0].address}
        for insn in instructions:
            is_control_flow = insn.groups and (CS_GRP_JUMP in insn.groups or CS_GRP_CALL in insn.groups or CS_GRP_RET in insn.groups)
            if is_control_flow:
                boundaries.add(insn.address + insn.size)
                if len(insn.operands) > 0 and insn.operands[0].type == CS_OP_IMM:
                    target = insn.operands[0].value.imm
                    if start_offset <= target <= end_offset:
                        boundaries.add(target)

        sorted_boundaries = sorted(list(boundaries))
        
        # 2. Create basic blocks
        blocks = {}
        addr_to_block_start = {}
        for i in range(len(sorted_boundaries)):
            start_addr = sorted_boundaries[i]
            end_addr = sorted_boundaries[i+1] if i + 1 < len(sorted_boundaries) else end_offset
            block_insns = [insn for insn in instructions if start_addr <= insn.address < end_addr]
            if block_insns:
                blocks[start_addr] = {'insns': block_insns, 'successors': []}
                for insn in block_insns:
                    addr_to_block_start[insn.address] = start_addr
        
        # 3. Find successors
        for start_addr, block_data in blocks.items():
            if not block_data['insns']: continue
            last_insn = block_data['insns'][-1]
            
            is_unconditional_jump = last_insn.mnemonic == 'jmp' or (CS_GRP_RET in last_insn.groups)
            if not is_unconditional_jump:
                next_addr = last_insn.address + last_insn.size
                if next_addr in addr_to_block_start:
                    blocks[start_addr]['successors'].append(addr_to_block_start[next_addr])

            if last_insn.groups and (CS_GRP_JUMP in last_insn.groups or CS_GRP_CALL in last_insn.groups):
                if len(last_insn.operands) > 0 and last_insn.operands[0].type == CS_OP_IMM:
                    target_addr = last_insn.operands[0].value.imm
                    if target_addr in addr_to_block_start:
                        blocks[start_addr]['successors'].append(addr_to_block_start[target_addr])

        # 4. Layout and Draw Graph
        nodes = {}
        positions = {}
        
        all_addrs = set(blocks.keys())
        non_root_addrs = {succ for start, data in blocks.items() for succ in data['successors'] if succ in all_addrs}
        roots = sorted(list(all_addrs - non_root_addrs))
        if not roots and all_addrs:
            roots = [sorted(list(all_addrs))[0]]

        level_counts = {}
        queue = [(root, 0) for root in roots]
        visited_bfs = set()

        while queue:
            addr, level = queue.pop(0)
            if addr in visited_bfs: continue
            visited_bfs.add(addr)

            x_pos = level_counts.get(level, 0) * 350
            y_pos = level * 150
            positions[addr] = (x_pos, y_pos)
            level_counts[level] = level_counts.get(level, 0) + 1

            for succ_addr in sorted(blocks[addr]['successors']):
                if succ_addr not in visited_bfs:
                    queue.append((succ_addr, level + 1))

        remaining_addrs = sorted(list(all_addrs - visited_bfs))
        y_offset = (max(level_counts.keys()) + 2) * 150 if level_counts else 0
        for i, addr in enumerate(remaining_addrs):
            positions[addr] = (i * 350, y_offset)

        for addr, block_data in blocks.items():
            block_text = f"<b>loc_{addr:X}</b><br>" + "<br>".join(f"{i.mnemonic} {i.op_str}" for i in block_data['insns'])
            
            text_item = QGraphicsTextItem()
            text_item.setHtml(f"<div style='background-color: #252526; color: #D4D4D4; padding: 5px; border-radius: 3px; border: 1px solid #3E3E42; font-family: Consolas; font-size: 10px;'>{block_text}</div>")
            
            if addr in positions:
                x, y = positions[addr]
                text_item.setPos(x, y)
            
            self.asm_roadmap_scene.addItem(text_item)
            nodes[addr] = text_item

        for start_addr, block_data in blocks.items():
            source_node = nodes.get(start_addr)
            if not source_node: continue
            
            for succ_addr in set(block_data['successors']):
                dest_node = nodes.get(succ_addr)
                if not dest_node: continue
                
                p1 = source_node.sceneBoundingRect().center()
                p2 = dest_node.sceneBoundingRect().center()
                
                line = Arrow(p1, p2)
                
                last_insn = block_data['insns'][-1]
                pen = QPen(QColor("gray"), 1.5)
                if last_insn.mnemonic == 'call':
                    pen.setColor(QColor("#569CD6")) # Blue
                elif last_insn.mnemonic.startswith('j') and not last_insn.mnemonic == 'jmp':
                    if succ_addr != (last_insn.address + last_insn.size):
                         pen.setColor(QColor("#6A9955")) # Green for jump taken
                    else:
                         pen.setColor(QColor("#D16969")) # Red for fall-through
                elif last_insn.mnemonic == 'jmp':
                    pen.setColor(QColor("#C586C0")) # Purple
                
                line.setPen(pen)
                line.setZValue(-1)
                self.asm_roadmap_scene.addItem(line)


    # --- Event Handlers and Slots ---
    @QtCore.Slot(int)
    def on_main_tab_changed(self, index):
        """Called when the user switches main tabs to update the view."""
        tab_text = self.main_tabs.tabText(index)
        if tab_text == "File Roadmap":
            self.update_roadmap()
        elif tab_text == "Call View":
            self.update_call_view()
        elif tab_text == "Assembly Roadmap":
            self.update_assembly_roadmap()

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
            a_offs = offs.get('a_offsets', [])
            b_offs = offs.get('b_offsets', [])
            center = 0
            if a_offs:
                center = a_offs[0]
            elif b_offs:
                center = b_offs[0]
            
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
        menu.addSeparator()
        menu.addAction("Go to Assembly Roadmap", self.go_to_assembly_roadmap)
        menu.exec(sender.mapToGlobal(pos))

    def go_to_assembly_roadmap(self):
        for i in range(self.main_tabs.count()):
            if self.main_tabs.tabText(i) == "Assembly Roadmap":
                self.main_tabs.setCurrentIndex(i)
                break

    def on_graph_context_menu(self, pos):
        menu = QtWidgets.QMenu()
        
        unified_action = menu.addAction("Unified View")
        focused_action = menu.addAction("Focused View")
        
        action = menu.exec(self.graph_view.mapToGlobal(pos))
        
        if action == unified_action:
            self.graph_view_mode = "unified"
            self.update_call_graph()
        elif action == focused_action:
            self.graph_view_mode = "focused"
            self.update_call_graph()

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
        task_id = self.add_task_to_manager(f"CAPA analysis on File {which}")
        
        worker = Worker(run_capa_analysis, path, capa_exe)
        worker.signals.result.connect(lambda res_path: self.on_capa_finished(which, res_path, task_id))
        worker.signals.error.connect(lambda err: self.update_task_in_manager(task_id, f"Error: {err[1]}"))
        self.threadpool.start(worker)

    def on_capa_finished(self, which, res_path, task_id):
        if res_path:
            try:
                with open(res_path, 'r', encoding='utf-8') as f:
                    results = f.read()
                
                parsed_matches = parse_capa_output(results)
                self.capa_matches = [m for m in self.capa_matches if m[0] != which]
                self.capa_matches.extend([(which, match) for match in parsed_matches])
                
                self.capa_editor.setPlainText(results)
                self._refresh_lists_and_views()
                self.update_task_in_manager(task_id, "Complete")
            except Exception as e:
                self.update_task_in_manager(task_id, f"Error reading results: {e}")
        else:
            self.update_task_in_manager(task_id, "Failed")

    def run_pe_feature_extraction(self, which=None, silent=False):
        target_which = which
        if not target_which:
            which_str, ok = QtWidgets.QInputDialog.getItem(self, "Select Target", "Extract features for:", ["File A", "File B"], 0, False)
            if not ok: return
            target_which = 'A' if which_str == "File A" else 'B'
        
        path = self.file_a_path if target_which == 'A' else self.file_b_path
        
        if not path:
            if not silent:
                QtWidgets.QMessageBox.warning(self, "No File", f"File {target_which} is not loaded.")
            return
        
        task_id = self.add_task_to_manager(f"Extracting PE features for File {target_which}")
        
        # Define a wrapper task to avoid passing unwanted arguments to the extractor
        def task(progress_callback, console_output_callback):
            return self.pe_extractor.extract_numeric_features(path)

        worker = Worker(task)
        worker.signals.result.connect(lambda features: self.on_pe_features_finished(target_which, features, task_id))
        worker.signals.error.connect(lambda err: self.update_task_in_manager(task_id, f"Error: {err[1]}"))
        self.threadpool.start(worker)

    def on_pe_features_finished(self, which, features, task_id):
        if "error" in features:
            self.update_task_in_manager(task_id, f"Error: {features['error']}")
            return

        if which == 'A':
            self.pe_features_a = features
        else:
            self.pe_features_b = features
        
        self.display_pe_features()
        self.update_task_in_manager(task_id, "Complete")
        
    def browse_for_clamav_db(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select ClamAV Database", filter="ClamAV DB (*.cvd *.cld *.ndb *.hdb *.ldb);;All files (*)")
        if path:
            self.clamav_db_path.setText(path)

    def on_clamav_command_change(self, text):
        if "--find-sigs" in text:
            self.clamav_command_arg_label.show()
            self.clamav_command_arg.show()
        else:
            self.clamav_command_arg_label.hide()
            self.clamav_command_arg.hide()

    def run_sigtool_from_gui(self):
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
        task_name = f"SigTool {command_str.split(' ')[0]}"

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
        
        self.run_generic_subprocess(command, self.clamav_console, task_name)

    def run_sigtool_decode(self):
        sigtool_path = os.path.join(script_dir, "clamav", "sigtool.exe")
        if not os.path.exists(sigtool_path):
            QtWidgets.QMessageBox.warning(self, "SigTool Not Found", f"Could not find sigtool.exe at: {sigtool_path}")
            return

        signatures_text = self.clamav_sig_input.toPlainText()
        if not signatures_text.strip():
            QtWidgets.QMessageBox.warning(self, "Input Missing", "Please paste one or more signatures to decode.")
            return
        
        command = [sigtool_path, "--decode-sigs"]
        self.run_generic_subprocess(command, self.clamav_console, "Decode Signatures", stdin_data=signatures_text)

    @QtCore.Slot()
    def display_pe_features(self):
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

        try:
            self.pe_features_output.setPlainText(json.dumps(features, indent=4))
            self.btn_generate_yara.setEnabled(True)
        except Exception as e:
            self.pe_features_output.setPlainText(f"Error formatting features: {e}")
            self.btn_generate_yara.setEnabled(False)

        self.resource_tree.clear()
        if features.get('resources'):
            for res in features['resources']:
                item = QtWidgets.QTreeWidgetItem([str(res.get(k, 'N/A')) for k in ['type_id', 'resource_id', 'lang_id', 'size']])
                self.resource_tree.addTopLevelItem(item)
        
        self.update_roadmap()
        self.update_call_view()
        self.update_assembly_roadmap()

    def prepare_yargen_for_current_file(self):
        which_str = self.pe_file_selector.currentText()
        path = self.file_a_path if which_str == "File A" else self.file_b_path

        if not path:
            QtWidgets.QMessageBox.warning(self, "No File", f"File {which_str} is not loaded.")
            return

        self.yargen_malware_path.setText(path)
        suggested_output = os.path.join(os.path.dirname(path), f"{Path(path).stem}_rules.yar")
        self.yargen_output_file.setText(suggested_output)

        for i in range(self.main_tabs.count()):
            if self.main_tabs.tabText(i) == "yarGen GUI":
                 self.main_tabs.setCurrentIndex(i)
                 break
        self.lbl_status.setText(f"yarGen GUI is ready for {os.path.basename(path)}.")

    def run_detectiteasy_scan(self):
        which_str, ok = QtWidgets.QInputDialog.getItem(self, "Select Target", "Run DiE on:", ["File A", "File B"], 0, False)
        if not ok: return
            
        path = self.file_a_path if which_str == "File A" else self.file_b_path
        if not path:
            QtWidgets.QMessageBox.warning(self, "No File", f"File {which_str} is not loaded.")
            return

        die_path = os.path.join(script_dir, "detectiteasy", "diec.exe")
        if not os.path.exists(die_path):
             QtWidgets.QMessageBox.warning(self, "DiE Not Found", f"Could not find diec.exe at: {die_path}")
             return

        command = [die_path, "-j", path]
        self.run_generic_subprocess(command, self.die_output, f"DetectItEasy on File {which_str[-1]}")

    def clear_all(self):
        self.file_a_path = self.file_b_path = self.yara_path = None
        self.file_a_data = self.file_b_data = None
        self.pe_features_a = self.pe_features_b = None
        self.matches_a = self.matches_b = []
        self.capa_matches = []
        self.diff_hunks = []
        self.yara_index = {}
        self._yara_keys = []
        
        self.hunk_list.clear()
        self.yara_list.clear()
        self.capa_list.clear()
        self.unified_view_a.clear()
        self.unified_view_b.clear()
        self.details.clear()
        self.yara_editor.clear()
        self.capa_editor.clear()
        self.pe_features_output.clear()
        self.resource_tree.clear()
        self.die_output.clear()
        self.clamav_console.clear()
        self.base64_input.clear()
        self.base64_output.clear()
        self.roadmap_scene.clear()
        self.call_view_tree.clear()
        self.asm_roadmap_scene.clear()
        self.task_table.setRowCount(0)
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
        dir_path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Directory to Exclude")
        if dir_path:
            self.excluded_rules_list.addItem(dir_path)
            self.load_excluded_rules()

    def remove_selected_excluded(self):
        for item in self.excluded_rules_list.selectedItems():
            self.excluded_rules_list.takeItem(self.excluded_rules_list.row(item))
        self.load_excluded_rules()

    def load_excluded_rules(self):
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
                            rule_names = re.findall(r"rule\s+([a-zA-Z0-9_]+)", content)
                            self.excluded_rules.update(rule_names)
                        except Exception as e:
                            logging.error(f"Error reading excluded rule file {rule_path}: {e}")
        
        self.lbl_status.setText(f"Loaded {len(self.excluded_rules)} excluded YARA rules.")

    def run_base64_encode(self):
        input_text = self.base64_input.toPlainText()
        if not input_text: return
        
        try:
            if self.base64_mode.currentText() == "Hex":
                input_bytes = binascii.unhexlify(input_text.replace(" ", ""))
            else:
                input_bytes = input_text.encode('utf-8')
            
            encoded_bytes = base64.b64encode(input_bytes)
            self.base64_output.setPlainText(encoded_bytes.decode('ascii'))
        except Exception as e:
            self.base64_output.setPlainText(f"Error: {e}")

    def run_base64_decode(self):
        input_text = self.base64_input.toPlainText()
        if not input_text: return
        
        try:
            decoded_bytes = base64.b64decode(input_text)
            
            if self.base64_mode.currentText() == "Hex":
                output_text = binascii.hexlify(decoded_bytes).decode('ascii')
            else:
                output_text = decoded_bytes.decode('utf-8', errors='replace')
            
            self.base64_output.setPlainText(output_text)
        except Exception as e:
            self.base64_output.setPlainText(f"Error: {e}")
            
    def filter_results(self, text):
        """Filter the lists in the Scan Results tab."""
        for i in range(self.hunk_list.count()):
            item = self.hunk_list.item(i)
            item.setHidden(text.lower() not in item.text().lower())
            
        for i in range(self.yara_list.count()):
            item = self.yara_list.item(i)
            item.setHidden(text.lower() not in item.text().lower())
            
        for i in range(self.capa_list.count()):
            item = self.capa_list.item(i)
            item.setHidden(text.lower() not in item.text().lower())

    def filter_pe_analysis(self, text):
        """Filter the PE Analysis tab content."""
        iterator = QtWidgets.QTreeWidgetItemIterator(self.resource_tree)
        while iterator.value():
            item = iterator.value()
            match = any(text.lower() in item.text(col).lower() for col in range(item.columnCount()))
            item.setHidden(not match)
            iterator += 1

    def filter_editors(self, text):
        """Search within the active editor."""
        editor = None
        current_tab_widget = self.main_tabs.currentWidget().findChild(QtWidgets.QTabWidget)
        if current_tab_widget:
            if current_tab_widget.currentWidget().objectName() == "YARA Editor":
                 editor = self.yara_editor
            elif current_tab_widget.currentWidget().objectName() == "CAPA Editor":
                 editor = self.capa_editor
        
        if editor:
            cursor = editor.textCursor()
            cursor.setPosition(0)
            editor.setTextCursor(cursor)
            
            extra_selections = []
            if text:
                color = QColor(Qt.yellow).lighter(160)
                while editor.find(text):
                    selection = QtWidgets.QTextEdit.ExtraSelection()
                    selection.format.setBackground(color)
                    selection.cursor = editor.textCursor()
                    extra_selections.append(selection)
            editor.setExtraSelections(extra_selections)

    # --- Task Management ---
    def add_task_to_manager(self, task_name: str) -> int:
        self.task_counter += 1
        task_id = self.task_counter
        
        row_position = self.task_table.rowCount()
        self.task_table.insertRow(row_position)
        
        self.task_table.setItem(row_position, 0, QTableWidgetItem(str(task_id)))
        self.task_table.setItem(row_position, 1, QTableWidgetItem(task_name))
        self.task_table.setItem(row_position, 2, QTableWidgetItem("Running..."))
        
        return task_id

    def update_task_in_manager(self, task_id: int, status: str):
        for row in range(self.task_table.rowCount()):
            if self.task_table.item(row, 0).text() == str(task_id):
                self.task_table.setItem(row, 2, QTableWidgetItem(status))
                break
    
    # --- Unpacker ---
    def run_unpacker(self, which: str):
        if not UNICORN_AVAILABLE:
            QtWidgets.QMessageBox.critical(self, "Unicorn Engine Not Found", "Please install the Unicorn Engine to use this feature: pip install unicorn")
            return

        path = self.file_a_path if which == 'A' else self.file_b_path
        if not path:
            QtWidgets.QMessageBox.warning(self, "No File", f"File {which} is not loaded.")
            return

        task_id = self.add_task_to_manager(f"Unpacking File {which}")
        self.unpacker_console.clear()

        # in run_unpacker.task(...)
        def task(progress_callback, console_output_callback):
            unpacker = EnhancedUnicornUnpacker(path, console_output_callback)
            res = unpacker.unpack()
            if not res:
                return {"ok": False, "msg": "Unpack failed"}

            # Persist big payloads to disk BEFORE emitting the result
            tmp_dir = os.path.join(os.getcwd(), "unpack_tmp")
            os.makedirs(tmp_dir, exist_ok=True)

            unpacked_path = None
            if res.get("unpacked_data"):
                unpacked_path = os.path.join(tmp_dir, f"{Path(path).stem}_unpacked.bin")
                with open(unpacked_path, "wb") as f:
                    f.write(res["unpacked_data"])
                # Free memory and avoid sending big bytes across the signal
                res["unpacked_data"] = None

            # (Optional) persist vmprotect decompressed sections too
            ds = res.get("decompressed_sections") or {}
            ds_paths = {}
            for rva, data in ds.items():
                outp = os.path.join(tmp_dir, f"{Path(path).stem}_vmp_{rva:08x}.bin")
                with open(outp, "wb") as f:
                    f.write(data)
                ds_paths[rva] = outp
            res["decompressed_section_paths"] = ds_paths

            res["unpacked_path"] = unpacked_path
            res["ok"] = True
            # remove heavy objects that don't need to cross the signal
            res.pop("original_pe", None)
            return res

        worker = Worker(task)
        worker.signals.console_output.connect(self.unpacker_console.appendPlainText)
        worker.signals.result.connect(lambda result: self.on_unpacker_finished(which, result, task_id))
        worker.signals.error.connect(lambda err: self.update_task_in_manager(task_id, f"Error: {err[1]}"))
        self.threadpool.start(worker)

    def on_unpack_clicked(self):
        unpacker = EnhancedUnicornUnpacker(file_path, console_output_callback=self.append_console)
        worker = Worker(unpacker.unpack)   # run in background
        worker.signals.result.connect(self.on_unpack_finished)
        worker.signals.console_output.connect(self.append_console)
        self.threadpool.start(worker)

    def save_unpacked_file(self, which: str):
        data = self.unpacked_data_a if which == 'A' else self.unpacked_data_b
        original_path = self.file_a_path if which == 'A' else self.file_b_path

        if not data:
            QtWidgets.QMessageBox.warning(self, "No Data", f"No unpacked data available for File {which}.")
            return

        default_name = Path(original_path).stem + "_unpacked.bin"
        save_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, f"Save Unpacked File {which}", default_name)

        if save_path:
            try:
                with open(save_path, 'wb') as f:
                    f.write(data)
                self.lbl_status.setText(f"Saved unpacked file to {save_path}")
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Save Error", f"Could not save file: {e}")


# --- Application Entry Point ---
def main():
    """Main function to create and run the application."""
    app = QtWidgets.QApplication(sys.argv)
    win = OpenHydraFileAnalyzer()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
