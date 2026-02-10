"""Badge generation for EAST reports."""

import io
import math
from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch
import numpy as np


# Color scheme from spec
COLORS = {
    "success": "#28a745",
    "warning": "#ffc107",
    "critical": "#dc3545",
    "info": "#17a2b8",
    "header": "#2c3e50",
    "light_gray": "#f8f9fa",
    "white": "#ffffff",
}

GRADE_COLORS = {
    "A+": "#1a9641",
    "A": "#28a745",
    "A-": "#4daf4a",
    "B+": "#7fbc41",
    "B": "#a6d854",
    "B-": "#ffc107",
    "C+": "#f0ad4e",
    "C": "#ff8c00",
    "C-": "#e67e22",
    "D": "#dc3545",
    "E": "#c0392b",
    "F": "#8b0000",
    "T": "#6c757d",
    "M": "#6c757d",
}


def create_grade_badge(grade: str, label: str = "", size: float = 2.0) -> io.BytesIO:
    """Create a circular grade badge image.

    Args:
        grade: The letter grade (A+, A, B, C, D, F, etc.)
        label: Optional label below the badge
        size: Size of the badge in inches

    Returns:
        BytesIO buffer containing the PNG image
    """
    fig, ax = plt.subplots(1, 1, figsize=(size, size + (0.5 if label else 0)), dpi=150)
    ax.set_xlim(-1.2, 1.2)
    ax.set_ylim(-1.2 - (0.4 if label else 0), 1.2)
    ax.set_aspect("equal")
    ax.axis("off")

    color = GRADE_COLORS.get(grade, "#6c757d")

    # Outer ring
    outer_circle = plt.Circle((0, 0), 1.0, color=color, fill=True, linewidth=0)
    ax.add_patch(outer_circle)

    # Inner circle (white)
    inner_circle = plt.Circle((0, 0), 0.78, color="white", fill=True, linewidth=0)
    ax.add_patch(inner_circle)

    # Inner colored circle (lighter)
    inner_colored = plt.Circle((0, 0), 0.72, color=color, alpha=0.12, fill=True, linewidth=0)
    ax.add_patch(inner_colored)

    # Grade text
    font_size = 32 if len(grade) <= 2 else 24
    ax.text(0, 0.02, grade, ha="center", va="center",
            fontsize=font_size, fontweight="bold", color=color,
            fontfamily="sans-serif")

    # Label below
    if label:
        ax.text(0, -1.35, label, ha="center", va="center",
                fontsize=10, color="#495057", fontfamily="sans-serif")

    plt.tight_layout(pad=0.1)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", transparent=True, dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf


def create_score_gauge(score: int, max_score: int = 100, label: str = "",
                       size: tuple[float, float] = (3.5, 2.2)) -> io.BytesIO:
    """Create a semi-circular gauge chart for scores.

    Args:
        score: The numeric score value
        max_score: Maximum possible score
        label: Label to display below the gauge
        size: Figure size (width, height)

    Returns:
        BytesIO buffer containing the PNG image
    """
    fig, ax = plt.subplots(1, 1, figsize=size, dpi=150)
    ax.set_xlim(-1.4, 1.4)
    ax.set_ylim(-0.5, 1.4)
    ax.set_aspect("equal")
    ax.axis("off")

    # Determine color based on score percentage
    pct = score / max_score if max_score > 0 else 0
    if pct >= 0.8:
        color = COLORS["success"]
    elif pct >= 0.5:
        color = COLORS["warning"]
    else:
        color = COLORS["critical"]

    # Background arc (gray)
    theta_bg = np.linspace(math.pi, 0, 100)
    x_bg = 1.1 * np.cos(theta_bg)
    y_bg = 1.1 * np.sin(theta_bg)
    for i in range(len(theta_bg) - 1):
        ax.plot([x_bg[i], x_bg[i+1]], [y_bg[i], y_bg[i+1]],
                color="#e9ecef", linewidth=18, solid_capstyle="round")

    # Score arc
    angle = math.pi * (1 - pct)
    theta_score = np.linspace(math.pi, angle, max(int(100 * pct), 2))
    x_sc = 1.1 * np.cos(theta_score)
    y_sc = 1.1 * np.sin(theta_score)
    for i in range(len(theta_score) - 1):
        ax.plot([x_sc[i], x_sc[i+1]], [y_sc[i], y_sc[i+1]],
                color=color, linewidth=18, solid_capstyle="round")

    # Score text
    ax.text(0, 0.35, str(score), ha="center", va="center",
            fontsize=36, fontweight="bold", color=color,
            fontfamily="sans-serif")

    # "out of" text
    ax.text(0, 0.0, f"/ {max_score}", ha="center", va="center",
            fontsize=14, color="#6c757d", fontfamily="sans-serif")

    # Label
    if label:
        ax.text(0, -0.35, label, ha="center", va="center",
                fontsize=11, color="#495057", fontweight="bold",
                fontfamily="sans-serif")

    plt.tight_layout(pad=0.1)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", transparent=True, dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf


def create_status_badge(text: str, status: str = "info",
                        size: tuple[float, float] = (2.5, 0.5)) -> io.BytesIO:
    """Create a rounded status badge (like GitHub badges).

    Args:
        text: Text to display in the badge
        status: One of 'success', 'warning', 'critical', 'info'
        size: Figure size (width, height)

    Returns:
        BytesIO buffer containing the PNG image
    """
    color = COLORS.get(status, COLORS["info"])

    fig, ax = plt.subplots(1, 1, figsize=size, dpi=150)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 2)
    ax.axis("off")

    badge = FancyBboxPatch(
        (0.2, 0.2), 9.6, 1.6,
        boxstyle="round,pad=0.3",
        facecolor=color,
        edgecolor="none",
    )
    ax.add_patch(badge)

    ax.text(5, 1.0, text, ha="center", va="center",
            fontsize=12, fontweight="bold", color="white",
            fontfamily="sans-serif")

    plt.tight_layout(pad=0)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", transparent=True, dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf


def create_pass_fail_indicator(passed: bool, label: str = "",
                               size: tuple[float, float] = (0.5, 0.5)) -> io.BytesIO:
    """Create a simple pass/fail circle indicator.

    Args:
        passed: True for pass (green), False for fail (red)
        label: Optional label next to the indicator

    Returns:
        BytesIO buffer containing the PNG image
    """
    color = COLORS["success"] if passed else COLORS["critical"]
    width = size[0] + (len(label) * 0.12 if label else 0)

    fig, ax = plt.subplots(1, 1, figsize=(width, size[1]), dpi=150)
    ax.set_xlim(-0.2, width * 2)
    ax.set_ylim(-0.5, 0.5)
    ax.set_aspect("equal")
    ax.axis("off")

    circle = plt.Circle((0.0, 0.0), 0.3, color=color, fill=True)
    ax.add_patch(circle)

    # Check or X mark
    if passed:
        ax.text(0.0, 0.0, "✓", ha="center", va="center",
                fontsize=10, color="white", fontweight="bold")
    else:
        ax.text(0.0, 0.0, "✗", ha="center", va="center",
                fontsize=10, color="white", fontweight="bold")

    if label:
        ax.text(0.55, 0.0, label, ha="left", va="center",
                fontsize=9, color="#333333", fontfamily="sans-serif")

    plt.tight_layout(pad=0)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", transparent=True, dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf
