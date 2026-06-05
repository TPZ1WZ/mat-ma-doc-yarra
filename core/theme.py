# ── Color palette ───────────────────────────────────────────────────
SB_BG      = "#0F2142"   # Deep navy sidebar
SB_ACTIVE  = "#1E4D9A"   # Active nav item
SB_HOVER   = "#1A3A6A"   # Hover state
SB_TEXT    = "#A8C8EE"   # Normal nav text
SB_ATXT    = "#FFFFFF"   # Active nav text
SB_LOGO    = "#FFFFFF"
SB_MUTED   = "#527BA8"   # Muted sidebar text

CONT_BG    = "#EDF1FA"   # Main content background
CARD_BG    = "#FFFFFF"   # Card background
CARD_BDR   = "#CDD8EE"   # Card border
CARD_SHD   = "#BCC8E4"   # Shadow edge color
DIVIDER    = "#DDE8F5"   # Divider

TEXT_H     = "#0E1E3A"   # Heading text
TEXT_N     = "#253450"   # Normal text
TEXT_M     = "#6B82A4"   # Muted / secondary text

ACE_BLUE   = "#2563EB"   # Primary action
ACE_GREEN  = "#16A34A"   # Success
ACE_RED    = "#DC2626"   # Danger
ACE_ORANGE = "#EA580C"   # Warning
ACE_PURPLE = "#7C3AED"   # Special
ACE_TEAL   = "#0D9488"   # Teal

STAT_BG    = "#E0E8F8"   # Status bar background
STAT_OK    = "#16A34A"
STAT_WARN  = "#EA580C"
STAT_ERR   = "#DC2626"

# ── Font definitions ────────────────────────────────────────────────
FONT_TITLE   = ("Segoe UI", 17, "bold")
FONT_HEAD    = ("Segoe UI", 12, "bold")
FONT_SUBHEAD = ("Segoe UI", 11, "bold")
FONT_NORMAL  = ("Segoe UI", 10)
FONT_SMALL   = ("Segoe UI", 9)
FONT_MONO    = ("Consolas", 10)
FONT_LOGO    = ("Segoe UI", 14, "bold")
FONT_LOGO_SM = ("Segoe UI", 9)
FONT_NAV     = ("Segoe UI", 10)
FONT_BTN     = ("Segoe UI", 10, "bold")
FONT_STAT    = ("Segoe UI", 8)

# ── Button helper ────────────────────────────────────────────────────
def btn(master, text, color, command, **kw):
    """Flat button with consistent padding."""
    import tkinter as tk
    b = tk.Button(
        master, text=text, command=command,
        font=FONT_BTN, bg=color, fg="#FFFFFF",
        activebackground=color, activeforeground="#FFFFFF",
        relief="flat", bd=0,
        padx=kw.pop("padx", 18), pady=kw.pop("pady", 7),
        cursor="hand2", **kw
    )
    return b

def card(master, **kw):
    """White card with border."""
    import tkinter as tk
    return tk.Frame(master, bg=CARD_BG, highlightbackground=CARD_BDR,
                    highlightthickness=1, **kw)

def shadow_card(master, padx=0, pady=0, **kw):
    """Card with a subtle drop-shadow using a dark offset frame."""
    import tkinter as tk
    # Shadow layer (darker frame offset down-right)
    shadow = tk.Frame(master, bg=CARD_SHD, **kw)
    # White card sits on top with 2px offset
    inner = tk.Frame(shadow, bg=CARD_BG,
                     highlightbackground=CARD_BDR, highlightthickness=1)
    inner.place(relx=0, rely=0, relwidth=1.0, relheight=1.0,
                x=0, y=0, width=-2, height=-2)
    return shadow, inner

def page_card(master, **kw):
    """Full-width card for form sections with shadow."""
    import tkinter as tk
    outer = tk.Frame(master, bg=CARD_SHD, **kw)
    inner = tk.Frame(outer, bg=CARD_BG, highlightbackground=CARD_BDR, highlightthickness=1)
    inner.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))
    return outer, inner

def section_title(master, text, color=None):
    """Section heading label."""
    import tkinter as tk
    return tk.Label(master, text=text, font=FONT_HEAD,
                    bg=CARD_BG, fg=color or TEXT_H, anchor="w")

def muted(master, text):
    """Muted annotation label."""
    import tkinter as tk
    return tk.Label(master, text=text, font=FONT_SMALL,
                    bg=CARD_BG, fg=TEXT_M, anchor="w")

def screen_title(master, text, bg=None):
    """Full-page heading."""
    import tkinter as tk
    return tk.Label(master, text=text, font=FONT_TITLE,
                    bg=bg or CONT_BG, fg=TEXT_H, anchor="w")

def divider(master, bg=None):
    """Horizontal 1px divider."""
    import tkinter as tk
    return tk.Frame(master, bg=bg or CARD_BDR, height=1)

def configure_ttk_styles():
    """Apply ttk styles for a cleaner modern look. Call once at startup."""
    from tkinter import ttk
    s = ttk.Style()
    try:
        s.theme_use("clam")
    except Exception:
        pass

    # Notebook (tab bar)
    s.configure("TNotebook", background=CONT_BG, borderwidth=0, tabmargins=[0, 0, 0, 0])
    s.configure("TNotebook.Tab",
                background="#D4DEF2", foreground=TEXT_N,
                font=("Segoe UI", 10), padding=[14, 6],
                borderwidth=0)
    s.map("TNotebook.Tab",
          background=[("selected", CARD_BG), ("active", "#E0E8F8")],
          foreground=[("selected", TEXT_H)])

    # Scrollbar - slim & subtle
    s.configure("Vertical.TScrollbar",
                troughcolor=CONT_BG, background=CARD_BDR,
                borderwidth=0, arrowsize=12)
    s.configure("Horizontal.TScrollbar",
                troughcolor=CONT_BG, background=CARD_BDR,
                borderwidth=0, arrowsize=12)

    # Treeview
    s.configure("Treeview",
                background=CARD_BG, foreground=TEXT_N,
                rowheight=26, font=("Segoe UI", 10),
                borderwidth=0, relief="flat")
    s.configure("Treeview.Heading",
                background="#E0E8F8", foreground=TEXT_H,
                font=("Segoe UI", 10, "bold"), borderwidth=0)
    s.map("Treeview",
          background=[("selected", ACE_BLUE)],
          foreground=[("selected", "#FFFFFF")])

    # Separator
    s.configure("TSeparator", background=CARD_BDR)

    # Progressbar
    s.configure("TProgressbar",
                troughcolor=CARD_BDR, background=ACE_BLUE,
                borderwidth=0, thickness=6)
