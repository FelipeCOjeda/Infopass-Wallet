# gui_wallet.py
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from core_bip84 import (
    KDF,
    ARGON2_AVAILABLE,
    derive_bip84_from_text,
    export_descriptors_txt,
    export_sparrow_like_json,
)

# Clipboard auto-clear delay (ms)
_CLIPBOARD_CLEAR_MS = 30_000  # 30 seconds


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("InfoPass → BIP84 (watch-only)")
        self.geometry("1020x820")

        self.result = None
        self.mnemonic_hidden = True
        self._clipboard_timer = None

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- UI ----------------
    def _build_ui(self):
        # ===== Top input area =====
        top = ttk.Frame(self, padding=12)
        top.pack(fill="x")

        ttk.Label(top, text="Fonte (texto):").grid(row=0, column=0, sticky="w")
        self.txt_fonte = tk.Text(top, height=8, wrap="word")
        self.txt_fonte.grid(row=1, column=0, columnspan=8, sticky="nsew", pady=(6, 12))

        # BIP39 passphrase
        ttk.Label(top, text="BIP39 passphrase (segredo):").grid(row=2, column=0, sticky="w")
        self.var_pass = tk.StringVar()
        self.ent_pass = ttk.Entry(top, textvariable=self.var_pass, show="*", width=42)
        self.ent_pass.grid(row=3, column=0, sticky="w", pady=(4, 0))

        self.var_show_pass = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Mostrar", variable=self.var_show_pass, command=self._toggle_pass)\
            .grid(row=3, column=1, sticky="w", padx=10, pady=(4, 0))

        # KDF selector
        ttk.Label(top, text="KDF:").grid(row=2, column=2, sticky="w")
        kdf_values = ["hkdf", "argon2id", "legacy"]
        self.var_kdf = tk.StringVar(value="hkdf")
        kdf_combo = ttk.Combobox(top, textvariable=self.var_kdf, values=kdf_values, state="readonly", width=10)
        kdf_combo.grid(row=3, column=2, sticky="w", pady=(4, 0))

        # Address counts
        ttk.Label(top, text="External /0/:").grid(row=2, column=3, sticky="w")
        self.var_ext = tk.IntVar(value=10)
        ttk.Spinbox(top, from_=2, to=500, textvariable=self.var_ext, width=7)\
            .grid(row=3, column=3, sticky="w", pady=(4, 0))

        ttk.Label(top, text="Change /1/:").grid(row=2, column=4, sticky="w")
        self.var_chg = tk.IntVar(value=10)
        ttk.Spinbox(top, from_=2, to=500, textvariable=self.var_chg, width=7)\
            .grid(row=3, column=4, sticky="w", pady=(4, 0))

        # Network
        ttk.Label(top, text="Rede:").grid(row=2, column=5, sticky="w")
        self.var_net = tk.StringVar(value="main")
        ttk.Combobox(top, textvariable=self.var_net, values=["main", "test"], state="readonly", width=7)\
            .grid(row=3, column=5, sticky="w", pady=(4, 0))

        # Account
        ttk.Label(top, text="Conta:").grid(row=2, column=6, sticky="w")
        self.var_acct = tk.IntVar(value=0)
        ttk.Spinbox(top, from_=0, to=100, textvariable=self.var_acct, width=6)\
            .grid(row=3, column=6, sticky="w", pady=(4, 0))

        # ===== Buttons =====
        btns = ttk.Frame(self, padding=(12, 0, 12, 12))
        btns.pack(fill="x")

        ttk.Button(btns, text="Gerar carteira", command=self.generate).pack(side="left")
        ttk.Button(btns, text="Revelar mnemonic", command=self.toggle_mnemonic).pack(side="left", padx=8)
        ttk.Button(btns, text="Copiar mnemonic", command=self.copy_mnemonic).pack(side="left", padx=8)
        ttk.Button(btns, text="Copiar addr/xpub/zpub", command=self.copy_bundle).pack(side="left", padx=8)
        ttk.Button(btns, text="Copiar descriptors", command=self.copy_descriptors).pack(side="left", padx=8)
        ttk.Button(btns, text="Limpar campos", command=self.clear_fields).pack(side="left", padx=8)

        ttk.Button(btns, text="Export Descriptors (.txt)", command=self.export_desc).pack(side="right")
        ttk.Button(btns, text="Export JSON (Sparrow-like)", command=self.export_json).pack(side="right", padx=8)

        # ===== Summary =====
        summ = ttk.LabelFrame(self, text="Resumo", padding=12)
        summ.pack(fill="x", padx=12, pady=(0, 12))

        self.lbl_kdf = ttk.Label(summ, text="KDF: -")
        self.lbl_kdf.pack(anchor="w")

        self.lbl_mfp = ttk.Label(summ, text="MFP: -")
        self.lbl_mfp.pack(anchor="w")

        self.lbl_der = ttk.Label(summ, text="Derivation: -")
        self.lbl_der.pack(anchor="w")

        self.lbl_xpub = ttk.Label(summ, text="xpub: -")
        self.lbl_xpub.pack(anchor="w")

        self.lbl_zpub = ttk.Label(summ, text="zpub: -")
        self.lbl_zpub.pack(anchor="w")

        self.mnemonic_var = tk.StringVar(value="(mnemonic escondida)")
        self.lbl_mn = ttk.Label(summ, textvariable=self.mnemonic_var, wraplength=980)
        self.lbl_mn.pack(anchor="w", pady=(10, 0))

        # ===== Tabs =====
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.tab_ext = ttk.Frame(nb, padding=8)
        self.tab_chg = ttk.Frame(nb, padding=8)
        nb.add(self.tab_ext, text="External /0/")
        nb.add(self.tab_chg, text="Change /1/")

        self.tree_ext = self._make_tree(self.tab_ext)
        self.tree_chg = self._make_tree(self.tab_chg)

        self.tree_ext.bind("<Double-1>", lambda e: self.copy_selected_address(self.tree_ext))
        self.tree_chg.bind("<Double-1>", lambda e: self.copy_selected_address(self.tree_chg))

        top.columnconfigure(0, weight=1)

    def _toggle_pass(self):
        self.ent_pass.configure(show="" if self.var_show_pass.get() else "*")

    def _make_tree(self, parent):
        cols = ("index", "path", "address")
        tree = ttk.Treeview(parent, columns=cols, show="headings", height=16)

        tree.heading("index", text="#")
        tree.heading("path", text="Path")
        tree.heading("address", text="Address")

        tree.column("index", width=50, anchor="e")
        tree.column("path", width=280)
        tree.column("address", width=600)

        tree.pack(fill="both", expand=True)

        sb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")

        return tree

    def _fill_tree(self, tree, items):
        tree.delete(*tree.get_children())
        for i, (path, addr) in enumerate(items):
            tree.insert("", "end", values=(i, path, addr))

    # ---------------- Clipboard with auto-clear ----------------
    def _safe_clipboard(self, text: str):
        """Copy to clipboard and schedule auto-clear after 30s."""
        if self._clipboard_timer:
            self.after_cancel(self._clipboard_timer)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        self._clipboard_timer = self.after(
            _CLIPBOARD_CLEAR_MS,
            self._clear_clipboard,
        )

    def _clear_clipboard(self):
        self.clipboard_clear()
        self.clipboard_append("")
        self.update()
        self._clipboard_timer = None

    # ---------------- Close confirmation ----------------
    def _on_close(self):
        if self.result:
            if not messagebox.askyesno(
                "Sair",
                "Há dados de carteira gerados.\nDeseja realmente fechar?"
            ):
                return
        self._clear_clipboard()
        self.destroy()

    # ---------------- Actions ----------------
    def clear_fields(self):
        self.txt_fonte.delete("1.0", "end")
        self.var_pass.set("")
        self.mnemonic_hidden = True
        self.mnemonic_var.set("(mnemonic escondida)")
        self.result = None
        self.lbl_kdf.config(text="KDF: -")
        self.lbl_mfp.config(text="MFP: -")
        self.lbl_der.config(text="Derivation: -")
        self.lbl_xpub.config(text="xpub: -")
        self.lbl_zpub.config(text="zpub: -")
        self._fill_tree(self.tree_ext, [])
        self._fill_tree(self.tree_chg, [])

    def generate(self):
        fonte = self.txt_fonte.get("1.0", "end").strip()
        pwd = self.var_pass.get()
        kdf_name = self.var_kdf.get()

        if not fonte:
            messagebox.showerror("Erro", "A Fonte (texto) está vazia.")
            return

        if pwd == "":
            if not messagebox.askyesno(
                "Aviso",
                "BIP39 passphrase está vazia.\nIsso fica MUITO mais frágil.\n\nContinuar mesmo assim?"
            ):
                return

        if kdf_name == "argon2id" and not ARGON2_AVAILABLE:
            messagebox.showerror(
                "Erro",
                "argon2-cffi não está instalado.\n\n"
                "Instale com:\n  pip install argon2-cffi"
            )
            return

        try:
            kdf = KDF(kdf_name)
            r = derive_bip84_from_text(
                fonte_text=fonte,
                bip39_passphrase=pwd,
                kdf=kdf,
                network=self.var_net.get(),
                account=int(self.var_acct.get()),
                external_count=int(self.var_ext.get()),
                change_count=int(self.var_chg.get()),
            )

            self.result = r
            self.mnemonic_hidden = True

            self.lbl_kdf.config(text=f"KDF: {r.kdf_used}")
            self.lbl_mfp.config(text=f"MFP: {r.master_fingerprint_hex.upper()}")
            self.lbl_der.config(text=f"Derivation: {r.derivation}")
            self.lbl_xpub.config(text=f"xpub: {r.xpub}")
            self.lbl_zpub.config(text=f"zpub: {r.zpub}")
            self.mnemonic_var.set("(mnemonic escondida)")

            self._fill_tree(self.tree_ext, r.external_addrs)
            self._fill_tree(self.tree_chg, r.change_addrs)

        except Exception as e:
            messagebox.showerror("Erro", f"Falhou ao gerar:\n{e}")

    def toggle_mnemonic(self):
        if not self.result:
            return
        self.mnemonic_hidden = not self.mnemonic_hidden
        self.mnemonic_var.set("(mnemonic escondida)" if self.mnemonic_hidden else self.result.mnemonic_24)

    def copy_mnemonic(self):
        if not self.result:
            return
        if self.mnemonic_hidden:
            messagebox.showwarning(
                "Mnemonic escondida",
                "A mnemonic está escondida.\n\nClique em 'Revelar mnemonic' primeiro."
            )
            return
        self._safe_clipboard(self.result.mnemonic_24)
        messagebox.showinfo("Copiado", "Mnemonic copiada (clipboard limpa em 30s).")

    def copy_bundle(self):
        if not self.result:
            return
        r = self.result
        a0 = r.external_addrs[0][1] if r.external_addrs else ""
        a1 = r.external_addrs[1][1] if len(r.external_addrs) > 1 else ""

        blob = (
            f"addr0: {a0}\n"
            f"addr1: {a1}\n"
            f"xpub: {r.xpub}\n"
            f"zpub: {r.zpub}\n"
            f"mfp: {r.master_fingerprint_hex.upper()}\n"
            f"derivation: {r.derivation}\n"
        )
        self._safe_clipboard(blob)
        messagebox.showinfo("Copiado", "addr0/addr1 + xpub/zpub copiados.")

    def copy_descriptors(self):
        if not self.result:
            return
        r = self.result
        blob = f"{r.desc_external}\n{r.desc_change}\n"
        self._safe_clipboard(blob)
        messagebox.showinfo("Copiado", "Descriptors copiados.")

    def copy_selected_address(self, tree):
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], "values")
        if len(vals) >= 3:
            addr = vals[2]
            self._safe_clipboard(addr)
            messagebox.showinfo("Copiado", f"Endereço copiado:\n{addr}")

    def export_desc(self):
        if not self.result:
            return
        path = filedialog.asksaveasfilename(
            title="Salvar descriptors",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            export_descriptors_txt(path, self.result)
            messagebox.showinfo("OK", f"Descriptors salvos em:\n{path}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def export_json(self):
        if not self.result:
            return
        path = filedialog.asksaveasfilename(
            title="Salvar JSON (Sparrow-like)",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            export_sparrow_like_json(path, self.result)
            messagebox.showinfo("OK", f"JSON salvo em:\n{path}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))


if __name__ == "__main__":
    App().mainloop()
