"""Persistent RAG (Retrieval-Augmented Generation) memory for exploit attempts."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("auvap.rag.memory")


def _safe_now() -> str:
    return datetime.utcnow().isoformat()


def _basic_metadata(vuln: Dict[str, Any], script: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Lightweight metadata used by both vector and simple memory backends."""

    script_excerpt = "\n".join(script.splitlines()[:20])
    metadata = {
        "vuln_id": vuln.get("vuln_id"),
        "timestamp": _safe_now(),
        "service": vuln.get("service"),
        "version": vuln.get("version"),
        "port": vuln.get("port"),
        "host": vuln.get("host"),
        "exploit_type": vuln.get("script_generation", {}).get("exploit_type"),
        "attack_vector": vuln.get("attack_vector"),
        "success": bool(result.get("success")),
        "error_message": result.get("error_message"),
        "evidence": result.get("evidence"),
        "script_excerpt": script_excerpt,
    }
    return metadata


class SimpleJSONMemorySystem:
    """Fallback memory store that keeps exploit history in JSON files."""

    def __init__(self, persist_directory: str, max_entries: int = 2000) -> None:
        self.persist_directory = Path(persist_directory)
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        self.max_entries = max_entries
        self.store_path = self.persist_directory / "simple_memory.json"
        self._data: List[Dict[str, Any]] = []
        self._load()
        logger.warning(
            "Using SimpleJSONMemorySystem fallback (vector embeddings unavailable)."
        )

    # Persistence helpers -------------------------------------------------
    def _load(self) -> None:
        if not self.store_path.exists():
            self._data = []
            return
        try:
            self._data = json.loads(self.store_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load simple memory store: %s", exc)
            self._data = []

    def _save(self) -> None:
        try:
            self.store_path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to persist simple memory store: %s", exc)

    # Public API ----------------------------------------------------------
    def store_execution_feedback(
        self,
        vuln: Dict[str, Any],
        script: str,
        result: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> str:
        metadata = _basic_metadata(vuln, script, result)
        entry_id = f"{metadata.get('vuln_id') or 'unknown'}-{metadata['timestamp']}"
        summary = self._summarize_entry(metadata)
        entry = {
            "id": entry_id,
            "metadata": metadata,
            "document": summary,
        }
        self._data.append(entry)
        if len(self._data) > self.max_entries:
            self._data = self._data[-self.max_entries :]
        self._save()
        return entry_id

    def retrieve_relevant_experience(self, vuln: Dict[str, Any], top_k: int = 5) -> Dict[str, Any]:
        def score(entry: Dict[str, Any]) -> int:
            metadata = entry.get("metadata", {})
            score_val = 0
            if metadata.get("service") == vuln.get("service"):
                score_val += 3
            if metadata.get("port") == vuln.get("port"):
                score_val += 2
            if metadata.get("exploit_type") == vuln.get("script_generation", {}).get("exploit_type"):
                score_val += 2
            if metadata.get("success"):
                score_val += 1
            return score_val

        successes = [e for e in self._data if e.get("metadata", {}).get("success")]
        failures = [e for e in self._data if not e.get("metadata", {}).get("success")]

        successes = sorted(successes, key=score, reverse=True)[:top_k]
        failures = sorted(failures, key=score, reverse=True)[:top_k]

        lessons = [
            {
                "id": f"lesson-{entry['id']}",
                "metadata": {"summary": entry["document"][:160]},
                "document": entry["document"],
            }
            for entry in (successes + failures)[:top_k]
        ]

        return {
            "successful_examples": successes,
            "failed_examples": failures,
            "lessons": lessons,
            "query": vuln.get("service"),
        }

    def get_statistics(self) -> Dict[str, int]:
        successes = sum(1 for entry in self._data if entry.get("metadata", {}).get("success"))
        failures = len(self._data) - successes
        return {
            "successful_exploits": successes,
            "failed_exploits": failures,
            "lessons_learned": min(len(self._data), 50),
        }

    def _summarize_entry(self, metadata: Dict[str, Any]) -> str:
        status = "succeeded" if metadata.get("success") else "failed"
        service = metadata.get("service") or "unknown service"
        error = metadata.get("error_message") or metadata.get("evidence") or "no evidence"
        return f"Exploit {status} for {service} (port {metadata.get('port')}): {error}".strip()


chromadb = importlib.import_module("chromadb") if importlib.util.find_spec("chromadb") else None  # type: ignore
Settings = None
if chromadb:
    chroma_config = importlib.util.find_spec("chromadb.config")
    if chroma_config:
        Settings = getattr(importlib.import_module("chromadb.config"), "Settings", None)

sentence_transformers = importlib.util.find_spec("sentence_transformers")
SentenceTransformer = (
    getattr(importlib.import_module("sentence_transformers"), "SentenceTransformer")
    if sentence_transformers
    else None
)

try:  # Prefer absolute import so tests run without package context
    from llm.openrouter_client import OpenRouterClient
except ImportError:  # pragma: no cover - fallback for package-relative execution
    from ..llm.openrouter_client import OpenRouterClient

_EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
_LESSON_MODEL = "tngtech/deepseek-r1t2-chimera:free"
_COLLECTION_NAMES = (
    "successful_exploits",
    "failed_exploits",
    "lessons_learned",
)
_TECHNIQUE_KEYWORDS = {
    "paramiko": ["paramiko"],
    "requests": ["requests"],
    "socket": ["socket"],
    "ftplib": ["ftplib"],
    "subprocess": ["subprocess"],
    "smbclient": ["smbclient", "smb.SMBConnection"],
    "mysql": ["mysql", "pymysql", "mysql.connector"],
    "mongodb": ["pymongo"],
    "brute_force": ["for password in", "credential", "wordlist"],
    "sql_injection": ["' OR 1=1", "UNION SELECT", "sqlmap"],
    "command_injection": [";", "&&", "shell"],
}


class RAGMemorySystem:
    """Persistent vector-backed memory of exploit execution outcomes."""

    def __init__(
        self,
        persist_directory: str,
        chroma_client: Optional[Any] = None,
        embedding_model: Optional[Any] = None,
    ) -> None:
        self.persist_directory = Path(persist_directory)
        self.persist_directory.mkdir(parents=True, exist_ok=True)

        self.client = chroma_client or self._create_chroma_client()
        self.embedder = embedding_model or self._create_embedder()

        self.collections = {
            name: self._get_or_create_collection(name)
            for name in _COLLECTION_NAMES
        }

        stats = self.get_statistics()
        logger.info(
            "RAG initialized | successes=%s failures=%s lessons=%s",
            stats.get("successful_exploits", 0),
            stats.get("failed_exploits", 0),
            stats.get("lessons_learned", 0),
        )

    # Creation helpers -----------------------------------------------------
    def _create_chroma_client(self) -> Any:
        if chromadb is None:
            raise ImportError(
                "chromadb is required unless a custom client is provided to RAGMemorySystem",
            )
        # Prefer the modern PersistentClient API (Chroma 1.3+);
        if hasattr(chromadb, "PersistentClient"):
            return chromadb.PersistentClient(path=str(self.persist_directory))

        # Fall back to legacy Settings-based initialization for older versions.
        if Settings is None:
            raise ImportError("chromadb Settings module unavailable")
        settings = Settings(
            chroma_db_impl="duckdb+parquet",
            persist_directory=str(self.persist_directory),
        )
        return chromadb.Client(settings=settings)

    def _create_embedder(self) -> Any:
        if SentenceTransformer is None:
            raise ImportError(
                "sentence-transformers is required unless a custom embedding model is provided",
            )
        return SentenceTransformer(_EMBEDDING_MODEL_NAME)

    def _get_or_create_collection(self, name: str) -> Any:
        return self.client.get_or_create_collection(
            name=name,
            metadata={"description": f"AUVAP {name.replace('_', ' ')}"},
        )

    # Public API -----------------------------------------------------------
    def store_execution_feedback(
        self,
        vuln: Dict[str, Any],
        script: str,
        result: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> str:
        """Store exploit execution outcome and optional lessons."""

        metadata = self._build_metadata(vuln, script, result)
        embedding_text = self._create_embedding_text(metadata)
        embedding = self._embed(embedding_text)
        entry_id = self._make_entry_id(metadata)

        collection_key = "successful_exploits" if result.get("success") else "failed_exploits"
        collection = self.collections[collection_key]

        collection.upsert(
            ids=[entry_id],
            embeddings=[embedding],
            metadatas=[metadata],
            documents=[embedding_text],
        )
        self._persist()

        if api_key:
            lessons = self._extract_lessons_with_llm(metadata, script, api_key)
            if lessons:
                self._store_lessons(lessons, embedding_text, entry_id)
        return entry_id

    def retrieve_relevant_experience(self, vuln: Dict[str, Any], top_k: int = 5) -> Dict[str, Any]:
        """Return similar past exploits for the supplied vulnerability."""

        query_text = self._create_query_text(vuln)
        embedding = self._embed(query_text)

        success = self.collections["successful_exploits"].query(
            query_embeddings=[embedding],
            n_results=top_k,
        )
        failure = self.collections["failed_exploits"].query(
            query_embeddings=[embedding],
            n_results=top_k,
        )
        lessons = self.collections["lessons_learned"].query(
            query_embeddings=[embedding],
            n_results=top_k,
        )

        return {
            "successful_examples": self._format_results(success),
            "failed_examples": self._format_results(failure),
            "lessons": self._format_results(lessons),
            "query": query_text,
        }

    def get_statistics(self) -> Dict[str, int]:
        """Return document counts per collection."""

        return {name: collection.count() for name, collection in self.collections.items()}

    # Metadata helpers -----------------------------------------------------
    def _build_metadata(self, vuln: Dict[str, Any], script: str, result: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = datetime.utcnow().isoformat()
        script_excerpt = self._extract_key_code(script)
        techniques = self._extract_techniques(script)
        metadata = {
            "vuln_id": vuln.get("vuln_id"),
            "timestamp": timestamp,
            "service": vuln.get("service"),
            "version": vuln.get("version"),
            "port": vuln.get("port"),
            "host": vuln.get("host"),
            "exploit_type": vuln.get("script_generation", {}).get("exploit_type"),
            "attack_vector": vuln.get("attack_vector"),
            "cvss": vuln.get("cvss"),
            "success": bool(result.get("success")),
            "execution_time": result.get("execution_time"),
            "error_message": result.get("error_message"),
            "evidence": result.get("evidence"),
            "script_hash": hashlib.md5(script.encode("utf-8")).hexdigest(),
            "script_excerpt": script_excerpt,
            "techniques_used": ", ".join(techniques) if techniques else "",
        }
        metadata["script_excerpt_lines"] = script_excerpt.count("\n") + 1 if script_excerpt else 0
        return metadata

    def _create_embedding_text(self, metadata: Dict[str, Any]) -> str:
        return " | ".join(
            filter(
                None,
                [
                    metadata.get("service"),
                    str(metadata.get("version")),
                    metadata.get("exploit_type"),
                    "success" if metadata.get("success") else "failure",
                    metadata.get("attack_vector"),
                    ",".join(metadata.get("techniques_used", [])),
                    metadata.get("error_message") or metadata.get("evidence"),
                ],
            )
        )

    def _create_query_text(self, vuln: Dict[str, Any]) -> str:
        return " | ".join(
            filter(
                None,
                [
                    vuln.get("service"),
                    str(vuln.get("version")),
                    vuln.get("priority"),
                    vuln.get("attack_vector"),
                    vuln.get("exploitability"),
                ],
            )
        )

    def _extract_key_code(self, script: str) -> str:
        lines = script.splitlines()
        imports = [line for line in lines if line.startswith("import") or line.startswith("from ")]
        excerpt_lines: List[str] = []
        in_function = False
        for line in lines:
            if line.startswith("def exploit"):
                in_function = True
            if in_function:
                excerpt_lines.append(line)
            if in_function and len(excerpt_lines) >= 12:
                break
        return "\n".join(imports[:5] + excerpt_lines)

    def _extract_techniques(self, script: str) -> List[str]:
        lower_script = script.lower()
        techniques = []
        for label, hints in _TECHNIQUE_KEYWORDS.items():
            if any(hint.lower() in lower_script for hint in hints):
                techniques.append(label)
        return sorted(set(techniques))

    def _embed(self, text: str) -> List[float]:
        vector = self.embedder.encode([text])[0]
        if isinstance(vector, list):
            return vector
        return vector.tolist()

    def _make_entry_id(self, metadata: Dict[str, Any]) -> str:
        base = metadata.get("vuln_id") or "unknown"
        suffix = metadata.get("script_hash", "")[:8]
        timestamp = metadata.get("timestamp", datetime.utcnow().isoformat())
        safe_ts = timestamp.replace(":", "-")
        return f"{base}-{safe_ts}-{suffix}"

    # Lessons handling -----------------------------------------------------
    def _extract_lessons_with_llm(
        self,
        metadata: Dict[str, Any],
        script: str,
        api_key: str,
    ) -> Optional[Dict[str, Any]]:
        try:
            client = OpenRouterClient(api_key=api_key, default_model=_LESSON_MODEL)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unable to initialize OpenRouter client for lessons: %s", exc)
            return None

        prompt = self._build_lessons_prompt(metadata, script)
        try:
            response = client.call_with_json_response(
                prompt=prompt,
                temperature=0.4,
                max_tokens=700,
            )
            return response
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to extract lessons via LLM: %s", exc)
            return None

    def _build_lessons_prompt(self, metadata: Dict[str, Any], script: str) -> str:
        outcome = "succeeded" if metadata.get("success") else "failed"
        excerpt = metadata.get("script_excerpt") or self._extract_key_code(script)
        evidence = metadata.get("evidence") or metadata.get("error_message")
        techniques = metadata.get('techniques_used', '')
        if isinstance(techniques, list):
            techniques = ', '.join(techniques)
        return f"""
Analyze the following exploit attempt outcome and extract structured lessons.
Outcome: {outcome}
Service: {metadata.get('service')} version={metadata.get('version')} exploit_type={metadata.get('exploit_type')}
Techniques used: {techniques}
Evidence/Error: {evidence}
Script excerpt:
{excerpt}

Return JSON:
{{
  "key_lessons": ["..."],
  "recommended_approach": "...",
  "avoid": "...",
  "techniques_that_worked": ["..."],
  "techniques_that_failed": ["..."]
}}
""".strip()

    def _store_lessons(self, lessons: Dict[str, Any], context: str, parent_id: str) -> None:
        text = json.dumps(lessons)
        metadata = {
            "parent_id": parent_id,
            "summary": lessons.get("recommended_approach"),
        }
        embedding = self._embed(text)
        collection = self.collections["lessons_learned"]
        collection.upsert(
            ids=[f"lesson-{parent_id}"],
            embeddings=[embedding],
            metadatas=[metadata],
            documents=[text],
        )
        self._persist()

    # Query result formatting ----------------------------------------------
    def _format_results(self, results: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not results or not results.get("ids"):
            return []
        formatted: List[Dict[str, Any]] = []
        ids = results.get("ids", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        documents = results.get("documents", [[]])[0]
        distances = results.get("distances", [[]])[0]
        for idx, entry_id in enumerate(ids):
            distance = distances[idx] if idx < len(distances) else None
            similarity = None if distance is None else max(0.0, 1 - float(distance))
            formatted.append(
                {
                    "id": entry_id,
                    "metadata": metadatas[idx] if idx < len(metadatas) else {},
                    "document": documents[idx] if idx < len(documents) else "",
                    "similarity": similarity,
                }
            )
        return formatted

    def _persist(self) -> None:
        if hasattr(self.client, "persist"):
            try:
                self.client.persist()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to persist RAG memory: %s", exc)


def create_memory_system(persist_directory: str, prefer_vector: bool = True) -> Any:
    """Return the best available memory backend for the current environment."""

    if prefer_vector:
        try:
            return RAGMemorySystem(persist_directory=persist_directory)
        except (ImportError, OSError, RuntimeError) as exc:
            logger.warning("Vector RAG backend unavailable, falling back to JSON store: %s", exc)

    return SimpleJSONMemorySystem(persist_directory=persist_directory)

