"""
Container Image Verification — Verify container image integrity and provenance.

Ensures that only trusted, signed container images are deployed as agent
sandboxes. Supports Cosign/Sigstore signature verification and digest pinning.

Security guarantees:
- Images must match a pinned SHA256 digest
- Optionally verified against Cosign signatures
- Prevents supply chain attacks via image tampering
"""

import subprocess
import logging
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Optional
from enum import Enum

logger = logging.getLogger("vibeshield.security.image")


class VerificationStatus(Enum):
    VERIFIED = "verified"
    DIGEST_MISMATCH = "digest_mismatch"
    SIGNATURE_INVALID = "signature_invalid"
    COSIGN_UNAVAILABLE = "cosign_unavailable"
    IMAGE_NOT_FOUND = "image_not_found"
    UNKNOWN = "unknown"


@dataclass
class ImageManifest:
    """Trusted container image reference."""
    name: str
    pinned_digest: str  # SHA256 digest (sha256:abc123...)
    cosign_key: Optional[str] = None  # Public key for Cosign verification
    allowed_architectures: list[str] = None  # e.g., ["linux/amd64", "linux/arm64"]

    def __post_init__(self):
        if self.allowed_architectures is None:
            self.allowed_architectures = ["linux/amd64", "linux/arm64"]


@dataclass
class VerificationResult:
    """Result of an image verification check."""
    status: VerificationStatus
    image: str
    digest: str
    expected_digest: str
    details: str = ""


class ImageVerifier:
    """
    Verifies container image integrity before deployment.

    Usage:
        verifier = ImageVerifier()
        verifier.add_trusted("vibeshield/base", "sha256:abc123...", cosign_key="...")
        result = verifier.verify("vibeshield/base")
        if result.status != VerificationStatus.VERIFIED:
            raise SecurityError(f"Image verification failed: {result.details}")
    """

    def __init__(self, require_signature: bool = False):
        self._trusted: dict[str, ImageManifest] = {}
        self.require_signature = require_signature

    def add_trusted(
        self,
        name: str,
        digest: str,
        cosign_key: Optional[str] = None,
        allowed_architectures: Optional[list[str]] = None,
    ):
        """Add a trusted image with pinned digest."""
        manifest = ImageManifest(
            name=name,
            pinned_digest=digest,
            cosign_key=cosign_key,
            allowed_architectures=allowed_architectures,
        )
        self._trusted[name] = manifest
        logger.info(f"Trusted image added: {name} ({digest[:24]}...)")

    def remove_trusted(self, name: str):
        """Remove a trusted image."""
        self._trusted.pop(name, None)

    def verify(self, image_ref: str) -> VerificationResult:
        """
        Verify a container image against trusted manifests.

        Args:
            image_ref: Image reference (name:tag or name@digest)

        Returns:
            VerificationResult with status and details
        """
        # Strip tag if present, use the name to look up trust
        image_name = re.sub(r'[:@].*', '', image_ref)

        if image_name not in self._trusted:
            return VerificationResult(
                status=VerificationStatus.IMAGE_NOT_FOUND,
                image=image_ref,
                digest="",
                expected_digest="",
                details=f"Image '{image_name}' is not in the trusted manifest",
            )

        manifest = self._trusted[image_name]

        # If image_ref already contains a digest, verify it matches
        if "@" in image_ref:
            provided_digest = image_ref.split("@")[1]
            if provided_digest != manifest.pinned_digest:
                return VerificationResult(
                    status=VerificationStatus.DIGEST_MISMATCH,
                    image=image_ref,
                    digest=provided_digest,
                    expected_digest=manifest.pinned_digest,
                    details="Provided digest does not match pinned digest",
                )
            actual_digest = provided_digest
        else:
            # Need to inspect the image to get its actual digest
            actual_digest = self._inspect_digest(image_ref)
            if not actual_digest:
                return VerificationResult(
                    status=VerificationStatus.IMAGE_NOT_FOUND,
                    image=image_ref,
                    digest="",
                    expected_digest=manifest.pinned_digest,
                    details="Could not inspect image digest",
                )

            if actual_digest != manifest.pinned_digest:
                return VerificationResult(
                    status=VerificationStatus.DIGEST_MISMATCH,
                    image=image_ref,
                    digest=actual_digest,
                    expected_digest=manifest.pinned_digest,
                    details="Image digest does not match pinned digest — possible tampering",
                )

        # Optional Cosign signature verification
        if manifest.cosign_key and self.require_signature:
            sig_result = self._verify_cosign(image_ref, manifest.cosign_key)
            if sig_result != VerificationStatus.VERIFIED:
                return VerificationResult(
                    status=sig_result,
                    image=image_ref,
                    digest=actual_digest,
                    expected_digest=manifest.pinned_digest,
                    details="Cosign signature verification failed",
                )

        logger.info(f"Image verified: {image_ref} ({actual_digest[:24]}...)")
        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            image=image_ref,
            digest=actual_digest,
            expected_digest=manifest.pinned_digest,
            details="Image integrity verified",
        )

    def _inspect_digest(self, image_ref: str) -> Optional[str]:
        """Use podman inspect to get the actual image digest."""
        try:
            result = subprocess.run(
                ["podman", "image", "inspect", image_ref, "--format", "{{.Digest}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception as e:
            logger.error(f"Failed to inspect image {image_ref}: {e}")
        return None

    def _verify_cosign(self, image_ref: str, public_key: str) -> VerificationStatus:
        """Verify Cosign signature for the image."""
        try:
            result = subprocess.run(
                [
                    "cosign", "verify",
                    "--key", public_key,
                    image_ref,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return VerificationStatus.VERIFIED
            else:
                logger.warning(f"Cosign verification failed: {result.stderr[:200]}")
                return VerificationStatus.SIGNATURE_INVALID
        except FileNotFoundError:
            logger.warning("Cosign binary not found — skipping signature verification")
            return VerificationStatus.COSIGN_UNAVAILABLE
        except Exception as e:
            logger.error(f"Cosign verification error: {e}")
            return VerificationStatus.UNKNOWN

    def list_trusted(self) -> list[dict]:
        """List all trusted image manifests."""
        return [
            {
                "name": m.name,
                "digest": m.pinned_digest,
                "cosign_enabled": m.cosign_key is not None,
                "architectures": m.allowed_architectures,
            }
            for m in self._trusted.values()
        ]
