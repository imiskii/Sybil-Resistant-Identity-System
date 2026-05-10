from __future__ import annotations

import base64
import io

import torch
from facenet_pytorch import InceptionResnetV1, MTCNN
from fastapi import HTTPException
from PIL import Image

# Module-level MTCNN singleton — initialised on first call to extract_embedding.
_mtcnn: MTCNN | None = None


def _get_mtcnn() -> MTCNN:
    global _mtcnn
    if _mtcnn is None:
        _mtcnn = MTCNN(image_size=160, keep_all=False, device="cpu")
    return _mtcnn


def load_model() -> InceptionResnetV1:
    """Load the FaceNet InceptionResnetV1 model pretrained on VGGFace2 in eval mode on CPU."""
    return InceptionResnetV1(pretrained="vggface2").eval()


def extract_embedding(image_b64: str, model: InceptionResnetV1) -> list[float]:
    """Extract a 512-dimensional facial embedding from a base64-encoded image.

    Raises HTTPException 422 if no face is detected in the image.
    """
    image_bytes = base64.b64decode(image_b64)
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

    mtcnn = _get_mtcnn()
    face_tensor: torch.Tensor | None = mtcnn(image)

    if face_tensor is None:
        raise HTTPException(status_code=422, detail="No face detected in the provided image.")

    with torch.no_grad():
        embedding: torch.Tensor = model(face_tensor.unsqueeze(0))

    return embedding.squeeze().tolist()
