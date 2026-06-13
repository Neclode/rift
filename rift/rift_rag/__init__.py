"""Rift RAG — local-first executable retrieval layer over the Rift corpus.

Pure stdlib + numpy. All embeddings/generation go through local Ollama.
"""

__all__ = ["embed", "chunk", "store"]
