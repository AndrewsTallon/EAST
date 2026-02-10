"""Chart generation for EAST reports."""

import io
import math
from datetime import datetime, timedelta
from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np

from east.visuals.badges import COLORS


def create_certificate_timeline(
    not_before: datetime,
    not_after: datetime,
    domain: str = "",
    size: tuple[float, float] = (6, 2.0),
) -> io.BytesIO:
    """Create a certificate validity timeline chart.

    Shows the certificate validity period with current date marker.
    """
    fig, ax = plt.subplots(1, 1, figsize=size, dpi=150)

    now = datetime.now()
    days_total = (not_after - not_before).days
    days_remaining = (not_after - now).days
    days_elapsed = (now - not_before).days

    # Determine color based on remaining time
    if days_remaining < 0:
        bar_color = COLORS["critical"]
        status = "EXPIRED"
    elif days_remaining < 30:
        bar_color = COLORS["critical"]
        status = f"{days_remaining} days remaining"
    elif days_remaining < 90:
        bar_color = COLORS["warning"]
        status = f"{days_remaining} days remaining"
    else:
        bar_color = COLORS["success"]
        status = f"{days_remaining} days remaining"

    # Background bar
    ax.barh(0, days_total, height=0.5, color="#e9ecef", left=0)

    # Elapsed bar
    elapsed = min(days_elapsed, days_total)
    ax.barh(0, elapsed, height=0.5, color=bar_color, alpha=0.7, left=0)

    # Current date marker
    if 0 <= days_elapsed <= days_total:
        ax.axvline(x=days_elapsed, color=COLORS["header"], linewidth=2, linestyle="--")
        ax.annotate("Today", xy=(days_elapsed, 0.35), fontsize=8,
                    ha="center", va="bottom", color=COLORS["header"],
                    fontweight="bold")

    # Labels
    ax.text(0, -0.5, not_before.strftime("%Y-%m-%d"),
            fontsize=8, ha="left", va="top", color="#6c757d")
    ax.text(days_total, -0.5, not_after.strftime("%Y-%m-%d"),
            fontsize=8, ha="right", va="top", color="#6c757d")

    ax.text(days_total / 2, -0.85, status,
            fontsize=10, ha="center", va="top", color=bar_color,
            fontweight="bold")

    ax.set_xlim(-days_total * 0.02, days_total * 1.02)
    ax.set_ylim(-1.2, 0.8)
    ax.axis("off")

    if domain:
        ax.set_title(f"Certificate Validity: {domain}", fontsize=11,
                     fontweight="bold", color=COLORS["header"], pad=10)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", transparent=False,
                facecolor="white", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf


def create_protocol_support_chart(
    protocols: dict[str, bool],
    size: tuple[float, float] = (5, 2.5),
) -> io.BytesIO:
    """Create a horizontal bar chart showing protocol support.

    Args:
        protocols: Dict of protocol name -> supported (True/False)
    """
    fig, ax = plt.subplots(1, 1, figsize=size, dpi=150)

    names = list(protocols.keys())
    supported = list(protocols.values())
    y_pos = range(len(names))

    colors = [COLORS["success"] if s else "#e9ecef" for s in supported]
    text_colors = ["white" if s else "#adb5bd" for s in supported]

    bars = ax.barh(y_pos, [1] * len(names), color=colors, height=0.6, edgecolor="none")

    for i, (bar, name, sup) in enumerate(zip(bars, names, supported)):
        label = f"  {name}"
        status = "✓ Supported" if sup else "✗ Not Supported"
        ax.text(0.02, i, label, ha="left", va="center",
                fontsize=9, color=text_colors[i], fontweight="bold")
        ax.text(0.98, i, status, ha="right", va="center",
                fontsize=8, color=text_colors[i])

    ax.set_xlim(0, 1)
    ax.set_ylim(-0.5, len(names) - 0.5)
    ax.invert_yaxis()
    ax.axis("off")
    ax.set_title("Protocol Support", fontsize=11, fontweight="bold",
                 color=COLORS["header"], pad=10)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", transparent=False,
                facecolor="white", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf


def create_security_headers_chart(
    headers: dict[str, bool],
    size: tuple[float, float] = (6, 3.5),
) -> io.BytesIO:
    """Create a visual checklist for security headers.

    Args:
        headers: Dict of header name -> present (True/False)
    """
    fig, ax = plt.subplots(1, 1, figsize=size, dpi=150)

    names = list(headers.keys())
    present = list(headers.values())
    n = len(names)

    ax.set_xlim(0, 10)
    ax.set_ylim(-0.5, n + 0.5)
    ax.axis("off")

    for i, (name, is_present) in enumerate(zip(names, present)):
        y = n - 1 - i

        # Alternating background
        if i % 2 == 0:
            rect = plt.Rectangle((0, y - 0.4), 10, 0.8,
                                 facecolor="#f8f9fa", edgecolor="none")
            ax.add_patch(rect)

        # Status icon
        if is_present:
            ax.text(0.5, y, "✓", ha="center", va="center",
                    fontsize=14, color=COLORS["success"], fontweight="bold")
        else:
            ax.text(0.5, y, "✗", ha="center", va="center",
                    fontsize=14, color=COLORS["critical"], fontweight="bold")

        # Header name
        ax.text(1.2, y, name, ha="left", va="center",
                fontsize=9, color="#333333", fontfamily="sans-serif")

        # Status text
        status_text = "Present" if is_present else "Missing"
        status_color = COLORS["success"] if is_present else COLORS["critical"]
        ax.text(9.5, y, status_text, ha="right", va="center",
                fontsize=9, color=status_color, fontweight="bold")

    ax.set_title("Security Headers", fontsize=11, fontweight="bold",
                 color=COLORS["header"], pad=10)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", transparent=False,
                facecolor="white", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf


def create_summary_dashboard(
    scores: dict[str, dict],
    size: tuple[float, float] = (7, 3),
) -> io.BytesIO:
    """Create an executive summary dashboard with multiple mini-gauges.

    Args:
        scores: Dict of test_name -> {"score": int, "max": int, "grade": str}
    """
    n = len(scores)
    if n == 0:
        n = 1

    fig, axes = plt.subplots(1, n, figsize=(size[0], size[1]), dpi=150)
    if n == 1:
        axes = [axes]

    for ax, (name, data) in zip(axes, scores.items()):
        score = data.get("score", 0)
        max_score = data.get("max", 100)
        grade = data.get("grade", "")

        pct = score / max_score if max_score > 0 else 0
        if pct >= 0.8:
            color = COLORS["success"]
        elif pct >= 0.5:
            color = COLORS["warning"]
        else:
            color = COLORS["critical"]

        ax.set_xlim(-1.3, 1.3)
        ax.set_ylim(-0.8, 1.4)
        ax.set_aspect("equal")
        ax.axis("off")

        # Background arc
        theta_bg = np.linspace(math.pi, 0, 100)
        for i in range(len(theta_bg) - 1):
            x = [1.0 * np.cos(theta_bg[i]), 1.0 * np.cos(theta_bg[i+1])]
            y = [1.0 * np.sin(theta_bg[i]), 1.0 * np.sin(theta_bg[i+1])]
            ax.plot(x, y, color="#e9ecef", linewidth=12, solid_capstyle="round")

        # Score arc
        angle = math.pi * (1 - pct)
        theta_sc = np.linspace(math.pi, angle, max(int(100 * pct), 2))
        for i in range(len(theta_sc) - 1):
            x = [1.0 * np.cos(theta_sc[i]), 1.0 * np.cos(theta_sc[i+1])]
            y = [1.0 * np.sin(theta_sc[i]), 1.0 * np.sin(theta_sc[i+1])]
            ax.plot(x, y, color=color, linewidth=12, solid_capstyle="round")

        # Grade or score
        display = grade if grade else str(score)
        ax.text(0, 0.3, display, ha="center", va="center",
                fontsize=22, fontweight="bold", color=color)

        # Label
        label = name.replace("_", " ").title()
        ax.text(0, -0.55, label, ha="center", va="center",
                fontsize=9, color="#495057", fontweight="bold")

    plt.tight_layout(pad=0.5)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", transparent=False,
                facecolor="white", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf
