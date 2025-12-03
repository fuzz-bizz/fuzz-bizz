# corpus.py
#
# Manages the fuzzing corpus - input seeds and discovered inputs.

import hashlib
import logging
import os
import shutil
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class CorpusManager:
    """
    Manages the fuzzing corpus directory.
    
    Handles:
    - Initial seed storage
    - Deduplication via content hashing
    - Corpus statistics
    """
    
    def __init__(self, corpus_dir: Path):
        """
        Initialize corpus manager.
        
        Args:
            corpus_dir: Directory to store corpus inputs
        """
        self.corpus_dir = Path(corpus_dir)
        self.input_dir = self.corpus_dir / "input"
        self.output_dir = self.corpus_dir / "output"
        
        # Create directories
        self.input_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Corpus initialized at {self.corpus_dir}")
    
    def add_seed(self, data: bytes, name: Optional[str] = None) -> Path:
        """
        Add a seed to the corpus.
        
        Seeds are named by their SHA256 hash to ensure deduplication.
        
        Args:
            data: Seed content as bytes
            name: Optional name prefix for the seed file
            
        Returns:
            Path to the saved seed file
        """
        # Hash the content for deduplication
        content_hash = hashlib.sha256(data).hexdigest()[:16]
        
        if name:
            filename = f"{name}_{content_hash}"
        else:
            filename = content_hash
        
        seed_path = self.input_dir / filename
        
        # Only write if doesn't exist (dedup)
        if not seed_path.exists():
            seed_path.write_bytes(data)
            logger.debug(f"Added seed: {filename} ({len(data)} bytes)")
        else:
            logger.debug(f"Seed already exists: {filename}")
        
        return seed_path
    
    def add_seeds(self, seeds: List[bytes]) -> List[Path]:
        """
        Add multiple seeds to the corpus.
        
        Args:
            seeds: List of seed bytes
            
        Returns:
            List of paths to saved seed files
        """
        paths = []
        for i, seed in enumerate(seeds):
            path = self.add_seed(seed, f"seed_{i}")
            paths.append(path)
        
        logger.info(f"Added {len(paths)} seeds to corpus")
        return paths
    
    def count(self) -> int:
        """Return number of inputs in the corpus."""
        return len(list(self.input_dir.iterdir()))
    
    def total_size(self) -> int:
        """Return total size of corpus in bytes."""
        total = 0
        for f in self.input_dir.iterdir():
            if f.is_file():
                total += f.stat().st_size
        return total
    
    def list_inputs(self) -> List[Path]:
        """List all input files in corpus."""
        return [f for f in self.input_dir.iterdir() if f.is_file()]
    
    def clear(self) -> None:
        """Clear all inputs from corpus."""
        for f in self.input_dir.iterdir():
            if f.is_file():
                f.unlink()
        logger.info("Corpus cleared")
    
    def copy_from(self, source_dir: Path) -> int:
        """
        Copy inputs from another directory into corpus.
        
        Args:
            source_dir: Directory containing input files
            
        Returns:
            Number of files copied
        """
        count = 0
        source_path = Path(source_dir)
        
        if not source_path.exists():
            logger.warning(f"Source directory does not exist: {source_dir}")
            return 0
        
        for f in source_path.iterdir():
            if f.is_file():
                data = f.read_bytes()
                self.add_seed(data, f.stem)
                count += 1
        
        logger.info(f"Copied {count} files from {source_dir}")
        return count
    
    def get_stats(self) -> dict:
        """Get corpus statistics."""
        inputs = self.list_inputs()
        sizes = [f.stat().st_size for f in inputs]
        
        return {
            "count": len(inputs),
            "total_size": sum(sizes),
            "avg_size": sum(sizes) / len(sizes) if sizes else 0,
            "min_size": min(sizes) if sizes else 0,
            "max_size": max(sizes) if sizes else 0,
        }
