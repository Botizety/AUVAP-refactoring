"""Tests for the RAGMemorySystem persistence and retrieval helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

import pytest  # type: ignore[import-not-found]

from rag.memory_system import RAGMemorySystem


class DummyEmbedder:
    """Simple embedder that maps text length to a 1-D vector."""

    def encode(self, texts: List[str]) -> List[List[float]]:  # pragma: no cover - exercised indirectly
        vectors = []
        for text in texts:
            vectors.append([float(len(text))])
        return vectors


@dataclass
class FakeCollection:
    name: str
    entries: List[Dict[str, Any]] = field(default_factory=list)

    def upsert(self, ids: List[str], embeddings: List[List[float]], metadatas: List[Dict[str, Any]], documents: List[str]) -> None:
        for idx, entry_id in enumerate(ids):
            self.entries.append(
                {
                    "id": entry_id,
                    "embedding": embeddings[idx],
                    "metadata": metadatas[idx],
                    "document": documents[idx],
                }
            )

    def query(self, query_embeddings: List[List[float]], n_results: int = 5) -> Dict[str, List[List[Any]]]:
        if not self.entries:
            return {"ids": [[]], "metadatas": [[]], "documents": [[]], "distances": [[]]}
        query_value = query_embeddings[0][0]
        ranked = sorted(
            self.entries,
            key=lambda entry: abs(entry["embedding"][0] - query_value),
        )[:n_results]
        ids = [[entry["id"] for entry in ranked]]
        metadatas = [[entry["metadata"] for entry in ranked]]
        documents = [[entry["document"] for entry in ranked]]
        distances = [[abs(entry["embedding"][0] - query_value) for entry in ranked]]
        return {
            "ids": ids,
            "metadatas": metadatas,
            "documents": documents,
            "distances": distances,
        }

    def count(self) -> int:
        return len(self.entries)


class FakeChromaClient:
    def __init__(self) -> None:
        self.collections: Dict[str, FakeCollection] = {}
        self.persist_called = False

    def get_or_create_collection(self, name: str, metadata: Dict[str, Any] | None = None) -> FakeCollection:
        if name not in self.collections:
            self.collections[name] = FakeCollection(name)
        return self.collections[name]

    def persist(self) -> None:
        self.persist_called = True


@pytest.fixture
def rag_system(tmp_path) -> RAGMemorySystem:
    client = FakeChromaClient()
    embedder = DummyEmbedder()
    return RAGMemorySystem(
        persist_directory=str(tmp_path),
        chroma_client=client,
        embedding_model=embedder,
    )


def _sample_vuln(vuln_id: str = "VULN-001") -> Dict[str, Any]:
    return {
        "vuln_id": vuln_id,
        "service": "ssh",
        "version": "7.4",
        "port": 22,
        "host": "192.168.1.10",
        "attack_vector": "Network",
        "cvss": 8.9,
        "script_generation": {"exploit_type": "default_creds"},
    }


def _sample_result(success: bool, evidence: str = "shell") -> Dict[str, Any]:
    return {
        "success": success,
        "execution_time": 1.23,
        "evidence": evidence if success else None,
        "error_message": None if success else "Authentication failed",
    }


def _sample_script() -> str:
    return """import paramiko\n\n\nDEFUALT_PASSWORDS = ['admin', 'password']\n\n\ndef exploit(target_ip, target_port):\n    for password in DEFUALT_PASSWORDS:\n        pass\n    return {'success': False, 'message': 'placeholder', 'evidence': None}\n"""


def test_store_execution_feedback_creates_success_entry(rag_system: RAGMemorySystem) -> None:
    entry_id = rag_system.store_execution_feedback(
        vuln=_sample_vuln(),
        script=_sample_script(),
        result=_sample_result(True, evidence="shell obtained"),
    )

    assert entry_id.startswith("VULN-001")
    stats = rag_system.get_statistics()
    assert stats["successful_exploits"] == 1
    assert stats["failed_exploits"] == 0


def test_retrieve_returns_examples_and_lessons(rag_system: RAGMemorySystem) -> None:
    rag_system.store_execution_feedback(
        vuln=_sample_vuln("VULN-010"),
        script=_sample_script(),
        result=_sample_result(True),
    )
    rag_system.store_execution_feedback(
        vuln=_sample_vuln("VULN-020"),
        script=_sample_script(),
        result=_sample_result(False),
    )

    data = rag_system.retrieve_relevant_experience(_sample_vuln())
    assert len(data["successful_examples"]) == 1
    assert len(data["failed_examples"]) == 1
    assert "ssh" in data["query"]


def test_statistics_reflect_counts(rag_system: RAGMemorySystem) -> None:
    rag_system.store_execution_feedback(
        vuln=_sample_vuln("VULN-030"),
        script=_sample_script(),
        result=_sample_result(False),
    )
    stats = rag_system.get_statistics()
    assert stats["failed_exploits"] == 1
    assert stats["successful_exploits"] == 0