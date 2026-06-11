"""
EMBER-style feature extraction for PE files.
Extracts ~2380 features matching the EMBER 2018 feature set.
"""
import lief
import numpy as np
from typing import Dict, List, Optional
import hashlib


class EmberFeatureExtractor:
    def __init__(self):
        self.feature_version = 2
        self._init_feature_maps()

    def _init_feature_maps(self):
        self.dll_imports = {}
        self.dll_counter = 0
        self.api_imports = {}
        self.api_counter = 0

    def extract(self, filepath: str) -> Dict[str, np.ndarray]:
        """Extract all EMBER feature groups."""
        try:
            binary = lief.parse(filepath)
            if not binary or not binary.header:
                return self._empty_features()
        except Exception:
            return self._empty_features()

        features = {}
        features.update(self._general_file_info(binary))
        features.update(self._header_features(binary))
        features.update(self._section_features(binary))
        features.update(self._import_features(binary))
        features.update(self._export_features(binary))
        features.update(self._string_features(binary))
        features.update(self._byte_histogram(filepath))
        features.update(self._byte_entropy_histogram(filepath))

        return features

    def _empty_features(self) -> Dict[str, np.ndarray]:
        return {
            'general': np.zeros(10, dtype=np.float32),
            'header': np.zeros(62, dtype=np.float32),
            'section': np.zeros(255, dtype=np.float32),
            'imports': np.zeros(1280, dtype=np.float32),
            'exports': np.zeros(128, dtype=np.float32),
            'strings': np.zeros(104, dtype=np.float32),
            'byte_hist': np.zeros(256, dtype=np.float32),
            'byte_entropy': np.zeros(256, dtype=np.float32),
        }

    def _general_file_info(self, binary) -> Dict[str, np.ndarray]:
        feats = np.zeros(10, dtype=np.float32)
        feats[0] = binary.header.sizeof_headers if binary.header else 0
        feats[1] = binary.optional_header.sizeof_code if binary.optional_header else 0
        feats[2] = binary.optional_header.sizeof_initialized_data if binary.optional_header else 0
        feats[3] = binary.optional_header.sizeof_uninitialized_data if binary.optional_header else 0
        feats[4] = binary.optional_header.sizeof_image if binary.optional_header else 0
        feats[5] = len(binary.sections)
        feats[6] = len(binary.imports) if binary.imports else 0
        feats[7] = len(binary.exported_functions) if binary.exported_functions else 0
        feats[8] = binary.optional_header.address_of_entry_point if binary.optional_header else 0
        feats[9] = binary.optional_header.base_of_code if binary.optional_header else 0
        return {'general': feats}

    def _header_features(self, binary) -> Dict[str, np.ndarray]:
        feats = np.zeros(62, dtype=np.float32)
        if not binary.header or not binary.optional_header:
            return {'header': feats}

        h = binary.header
        oh = binary.optional_header

        feats[0] = h.machine
        feats[1] = h.numberof_sections
        feats[2] = h.time_date_stamps
        feats[3] = h.pointerto_symbol_table
        feats[4] = h.numberof_symbols
        feats[5] = h.sizeof_optional_header
        feats[6] = h.characteristics

        feats[7] = oh.magic
        feats[8] = oh.major_linker_version
        feats[9] = oh.minor_linker_version
        feats[10] = oh.sizeof_code
        feats[11] = oh.sizeof_initialized_data
        feats[12] = oh.sizeof_uninitialized_data
        feats[13] = oh.addressof_entrypoint
        feats[14] = oh.baseof_code
        feats[15] = oh.imagebase
        feats[16] = oh.section_alignment
        feats[17] = oh.file_alignment
        feats[18] = oh.major_operating_system_version
        feats[19] = oh.minor_operating_system_version
        feats[20] = oh.major_image_version
        feats[21] = oh.minor_image_version
        feats[22] = oh.major_subsystem_version
        feats[23] = oh.minor_subsystem_version
        feats[24] = oh.win32_version_value
        feats[25] = oh.sizeof_image
        feats[26] = oh.sizeof_headers
        feats[27] = oh.checksum
        feats[28] = oh.subsystem
        feats[29] = oh.dll_characteristics
        feats[30] = oh.sizeof_stack_reserve
        feats[31] = oh.sizeof_stack_commit
        feats[32] = oh.sizeof_heap_reserve
        feats[33] = oh.sizeof_heap_commit
        feats[34] = oh.loader_flags
        feats[35] = oh.numberof_rva_and_sizes

        data_dirs = oh.data_directories
        for i, d in enumerate(data_dirs[:10]):
            feats[36 + i*2] = d.rva
            feats[36 + i*2 + 1] = d.size

        return {'header': feats}

    def _section_features(self, binary) -> Dict[str, np.ndarray]:
        feats = np.zeros(255, dtype=np.float32)
        if not binary.sections:
            return {'section': feats}

        entropies = []
        sizes = []
        phys_sizes = []
        virtual_sizes = []
        characteristics = []

        for i, sec in enumerate(binary.sections[:5]):
            idx = i * 51
            if idx >= 255:
                break
            entropies.append(sec.entropy)
            sizes.append(sec.size)
            phys_sizes.append(sec.sizeof_raw_data)
            virtual_sizes.append(sec.virtual_size)
            characteristics.append(sec.characteristics)

            name_hash = hash(sec.name) % 1000
            feats[idx] = name_hash / 1000.0

        if entropies:
            feats[255-5] = np.mean(entropies)
            feats[255-4] = np.max(entropies)
            feats[255-3] = np.min(entropies)
            feats[255-2] = np.mean(sizes)
            feats[255-1] = np.mean(phys_sizes)

        return {'section': feats}

    def _import_features(self, binary) -> Dict[str, np.ndarray]:
        feats = np.zeros(1280, dtype=np.float32)
        if not binary.imports:
            return {'imports': feats}

        for imp in binary.imports:
            dll_name = imp.name.lower() if imp.name else ""
            dll_hash = self._get_or_create_hash(dll_name, self.dll_imports, self.dll_counter)
            if dll_hash < 256:
                feats[dll_hash] = 1.0

            for entry in imp.entries:
                api_name = entry.name.lower() if entry.name else ""
                api_hash = self._get_or_create_hash(api_name, self.api_imports, self.api_counter)
                if api_hash < 1024:
                    feats[256 + api_hash] = 1.0

        return {'imports': feats}

    def _get_or_create_hash(self, name: str, mapping: dict, counter: int) -> int:
        if name in mapping:
            return mapping[name]
        h = hash(name) % 1024
        mapping[name] = h
        return h

    def _export_features(self, binary) -> Dict[str, np.ndarray]:
        feats = np.zeros(128, dtype=np.float32)
        if not binary.exported_functions:
            return {'exports': feats}

        for i, exp in enumerate(binary.exported_functions[:128]):
            name = exp.name.lower() if exp.name else ""
            feats[i] = hash(name) % 10000 / 10000.0

        return {'exports': feats}

    def _string_features(self, binary) -> Dict[str, np.ndarray]:
        feats = np.zeros(104, dtype=np.float32)
        strings = []

        for sec in binary.sections:
            if sec.content.size > 0:
                try:
                    content = bytes(sec.content)
                    strings.extend(self._extract_strings(content))
                except Exception:
                    pass

        if not strings:
            return {'strings': feats}

        all_strings = " ".join(strings).lower()
        feats[0] = len(strings)
        feats[1] = np.mean([len(s) for s in strings]) if strings else 0
        feats[2] = len(all_strings)

        suspicious = ['http', 'https', 'ftp', 'cmd', 'powershell', 'wscript', 'cscript',
                      'regsvr32', 'rundll32', 'certutil', 'bitsadmin', 'wmic',
                      'createobject', 'wscript.shell', 'shell.application',
                      'virtualalloc', 'writeprocessmemory', 'createremotethread',
                      'getprocaddress', 'loadlibrary', 'freezedry', 'antivirus',
                      'firewall', 'defender', 'malware', 'virus', 'trojan',
                      'backdoor', 'keylogger', 'ransom', 'encrypt', 'decrypt',
                      'bitcoin', 'wallet', 'miner', 'pool', 'stratum']

        for i, term in enumerate(suspicious[:100]):
            feats[4 + i] = all_strings.count(term)

        return {'strings': feats}

    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        strings = []
        current = []
        for b in data:
            if 32 <= b <= 126:
                current.append(chr(b))
            else:
                if len(current) >= min_len:
                    strings.append(''.join(current))
                current = []
        if len(current) >= min_len:
            strings.append(''.join(current))
        return strings

    def _byte_histogram(self, filepath: str) -> Dict[str, np.ndarray]:
        feats = np.zeros(256, dtype=np.float32)
        try:
            with open(filepath, 'rb') as f:
                data = f.read(1_000_000)
            if data:
                hist, _ = np.histogram(list(data), bins=256, range=(0, 256), density=True)
                feats = hist.astype(np.float32)
        except Exception:
            pass
        return {'byte_hist': feats}

    def _byte_entropy_histogram(self, filepath: str) -> Dict[str, np.ndarray]:
        feats = np.zeros(256, dtype=np.float32)
        try:
            with open(filepath, 'rb') as f:
                data = f.read(1_000_000)
            if len(data) < 256:
                return {'byte_entropy': feats}

            window = 256
            entropies = []
            for i in range(0, len(data) - window, window // 4):
                chunk = data[i:i+window]
                hist, _ = np.histogram(list(chunk), bins=256, range=(0, 256), density=True)
                hist = hist[hist > 0]
                entropy = -np.sum(hist * np.log2(hist))
                entropies.append(entropy)

            if entropies:
                hist, _ = np.histogram(entropies, bins=256, range=(0, 8), density=True)
                feats = hist.astype(np.float32)
        except Exception:
            pass
        return {'byte_entropy': feats}

    def flatten(self, features: Dict[str, np.ndarray]) -> np.ndarray:
        """Concatenate all feature groups into single vector."""
        order = ['general', 'header', 'section', 'imports', 'exports', 'strings', 'byte_hist', 'byte_entropy']
        return np.concatenate([features[k] for k in order]).astype(np.float32)


def extract_ember_features(filepath: str) -> np.ndarray:
    extractor = EmberFeatureExtractor()
    features = extractor.extract(filepath)
    return extractor.flatten(features)