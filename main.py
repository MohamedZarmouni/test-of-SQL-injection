import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib

class BankApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Banque App - Connexion")
        self.root.geometry("400x500")
        self.root.configure(bg="#2c3e50")
        
        # Initialiser la base de données
        self.init_database()
        
        # Afficher l'écran de connexion
        self.show_login_screen()
        
    def init_database(self):
        """Initialise la base de données SQLite"""
        conn = sqlite3.connect('bank.db')
        cursor = conn.cursor()
        
        # Créer la table des utilisateurs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                solde REAL DEFAULT 1000.0
            )
        ''')
        
        try:
            cursor.execute("INSERT INTO users (username, password, solde) VALUES (?, ?, ?)",
                         ('admin', hashlib.sha256('admin123'.encode()).hexdigest(), 5000.0))
            cursor.execute("INSERT INTO users (username, password, solde) VALUES (?, ?, ?)",
                         ('user1', hashlib.sha256('password'.encode()).hexdigest(), 1500.0))
            cursor.execute("INSERT INTO users (username, password, solde) VALUES (?, ?, ?)",
                         ('alice', hashlib.sha256('alice2024'.encode()).hexdigest(), 2500.0))
        except sqlite3.IntegrityError:
            pass  # Les utilisateurs existent déjà
        
        conn.commit()
        conn.close()
        
    def clear_window(self):
        """Efface tous les widgets de la fenêtre"""
        for widget in self.root.winfo_children():
            widget.destroy()
            
    def show_login_screen(self):
        """Affiche l'écran de connexion"""
        self.clear_window()
        self.root.title("Banque App - Connexion")
        
        # Frame principal
        frame = tk.Frame(self.root, bg="#2c3e50")
        frame.pack(expand=True, fill="both", padx=20, pady=20)
        
        # Titre
        title = tk.Label(frame, text="🏦 BANQUE APP", font=("Arial", 24, "bold"),
                        bg="#2c3e50", fg="#ecf0f1")
        title.pack(pady=20)
        
        # Avertissement de vulnérabilité
        warning = tk.Label(frame, text="⚠️ just a eduction app ",
                          font=("Arial", 10), bg="#e74c3c", fg="white", padx=10, pady=5)
        warning.pack(pady=10)
        
        # Username
        tk.Label(frame, text="Nom d'utilisateur:", font=("Arial", 12),
                bg="#2c3e50", fg="#ecf0f1").pack(pady=(20, 5))
        self.username_entry = tk.Entry(frame, font=("Arial", 12), width=30)
        self.username_entry.pack(pady=5)
        
        # Password
        tk.Label(frame, text="Mot de passe:", font=("Arial", 12),
                bg="#2c3e50", fg="#ecf0f1").pack(pady=(10, 5))
        self.password_entry = tk.Entry(frame, font=("Arial", 12), width=30, show="*")
        self.password_entry.pack(pady=5)
        
        # Boutons
        btn_frame = tk.Frame(frame, bg="#2c3e50")
        btn_frame.pack(pady=20)
        
        login_btn = tk.Button(btn_frame, text="Se connecter", font=("Arial", 12, "bold"),
                             bg="#27ae60", fg="white", width=15, command=self.login_vulnerable)
        login_btn.grid(row=0, column=0, padx=5)
        
        create_btn = tk.Button(btn_frame, text="Créer un compte", font=("Arial", 12),
                              bg="#3498db", fg="white", width=15, command=self.show_create_account)
        create_btn.grid(row=0, column=1, padx=5)
        
        # Instructions pour exploit
        exploit_frame = tk.Frame(frame, bg="#34495e", relief="solid", borderwidth=1)
        exploit_frame.pack(pady=20, padx=10, fill="x")
        
        tk.Label(exploit_frame, text="💡 Test SQL Injection", font=("Arial", 11, "bold"),
                bg="#34495e", fg="#f39c12").pack(pady=5)
        
        exploit_text = """Essayez ces injections SQL dans le champ username:

1. ' OR '1'='1' -- 
   (Se connecter sans mot de passe)

2. admin' --
   (Se connecter en tant qu'admin)

3. ' OR 1=1 UNION SELECT id, username, password, 9999 FROM users --
   (Voir tous les comptes)"""
        
        tk.Label(exploit_frame, text=exploit_text, font=("Arial", 9),
                bg="#34495e", fg="#ecf0f1", justify="left").pack(pady=5, padx=10)
        
    def login_vulnerable(self):
        """Connexion VULNÉRABLE avec SQL Injection"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs")
            return
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect('bank.db')
        cursor = conn.cursor()
        
       


        query = f"SELECT username, solde FROM users WHERE username=%s AND password='{hashed_password}'"
        
        print(f"Requête SQL exécutée: {query}") 
        
        try:
            cursor.execute(query,(username,))
            result = cursor.fetchone()
            
            if result:
                username_db, solde = result
                messagebox.showinfo("Succès", f"Connexion réussie!\nBienvenue {username_db}")
                self.show_dashboard(username_db, solde)
            else:
                messagebox.showerror("Erreur", "Nom d'utilisateur ou mot de passe incorrect")
        except sqlite3.Error as e:
            messagebox.showerror("Erreur SQL", f"Erreur: {str(e)}\n\nRequête: {query}")
        finally:
            conn.close()
            
    def show_create_account(self):
        """Affiche l'écran de création de compte"""
        self.clear_window()
        self.root.title("Créer un compte")
        
        frame = tk.Frame(self.root, bg="#2c3e50")
        frame.pack(expand=True, fill="both", padx=20, pady=20)
        
        # Titre
        title = tk.Label(frame, text="📝 Créer un nouveau compte", font=("Arial", 20, "bold"),
                        bg="#2c3e50", fg="#ecf0f1")
        title.pack(pady=20)
        
        # Username
        tk.Label(frame, text="Nom d'utilisateur:", font=("Arial", 12),
                bg="#2c3e50", fg="#ecf0f1").pack(pady=(10, 5))
        self.new_username_entry = tk.Entry(frame, font=("Arial", 12), width=30)
        self.new_username_entry.pack(pady=5)
        
        # Password
        tk.Label(frame, text="Mot de passe:", font=("Arial", 12),
                bg="#2c3e50", fg="#ecf0f1").pack(pady=(10, 5))
        self.new_password_entry = tk.Entry(frame, font=("Arial", 12), width=30, show="*")
        self.new_password_entry.pack(pady=5)
        
        # Confirm Password
        tk.Label(frame, text="Confirmer le mot de passe:", font=("Arial", 12),
                bg="#2c3e50", fg="#ecf0f1").pack(pady=(10, 5))
        self.confirm_password_entry = tk.Entry(frame, font=("Arial", 12), width=30, show="*")
        self.confirm_password_entry.pack(pady=5)
        
        # Solde initial
        tk.Label(frame, text="Solde initial (€):", font=("Arial", 12),
                bg="#2c3e50", fg="#ecf0f1").pack(pady=(10, 5))
        self.initial_balance_entry = tk.Entry(frame, font=("Arial", 12), width=30)
        self.initial_balance_entry.insert(0, "1000.0")
        self.initial_balance_entry.pack(pady=5)
        
        # Boutons
        btn_frame = tk.Frame(frame, bg="#2c3e50")
        btn_frame.pack(pady=20)
        
        create_btn = tk.Button(btn_frame, text="Créer", font=("Arial", 12, "bold"),
                              bg="#27ae60", fg="white", width=15, command=self.create_account)
        create_btn.grid(row=0, column=0, padx=5)
        
        back_btn = tk.Button(btn_frame, text="Retour", font=("Arial", 12),
                            bg="#95a5a6", fg="white", width=15, command=self.show_login_screen)
        back_btn.grid(row=0, column=1, padx=5)
        
    def create_account(self):
        """Crée un nouveau compte utilisateur"""
        username = self.new_username_entry.get()
        password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        try:
            initial_balance = float(self.initial_balance_entry.get())
        except ValueError:
            messagebox.showerror("Erreur", "Le solde doit être un nombre valide")
            return
        
        if not username or not password:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs")
            return
        
        if password != confirm_password:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas")
            return
        
        if len(password) < 6:
            messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins 6 caractères")
            return
        
        # Hasher le mot de passe
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Insérer dans la base de données (cette partie est sécurisée avec des paramètres)
        conn = sqlite3.connect('bank.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO users (username, password, solde) VALUES (?, ?, ?)",
                         (username, hashed_password, initial_balance))
            conn.commit()
            messagebox.showinfo("Succès", f"Compte créé avec succès!\nBienvenue {username}")
            self.show_dashboard(username, initial_balance)
        except sqlite3.IntegrityError:
            messagebox.showerror("Erreur", "Ce nom d'utilisateur existe déjà")
        finally:
            conn.close()
            
    def show_dashboard(self, username, solde):
        """Affiche le tableau de bord de l'utilisateur"""
        self.clear_window()
        self.root.title(f"Tableau de bord - {username}")
        
        frame = tk.Frame(self.root, bg="#2c3e50")
        frame.pack(expand=True, fill="both", padx=20, pady=20)
        
        # Titre
        title = tk.Label(frame, text=f"👤 Bienvenue, {username}!", font=("Arial", 24, "bold"),
                        bg="#2c3e50", fg="#ecf0f1")
        title.pack(pady=20)
        
        # Carte de solde
        balance_frame = tk.Frame(frame, bg="#27ae60", relief="raised", borderwidth=3)
        balance_frame.pack(pady=20, padx=40, fill="x")
        
        tk.Label(balance_frame, text="💰 VOTRE SOLDE", font=("Arial", 14, "bold"),
                bg="#27ae60", fg="white").pack(pady=10)
        
        tk.Label(balance_frame, text=f"{solde:.2f} €", font=("Arial", 32, "bold"),
                bg="#27ae60", fg="white").pack(pady=10)
        
        # Informations
        info_frame = tk.Frame(frame, bg="#34495e", relief="solid", borderwidth=1)
        info_frame.pack(pady=20, padx=40, fill="x")
        
        tk.Label(info_frame, text="ℹ️ Informations du compte", font=("Arial", 12, "bold"),
                bg="#34495e", fg="#f39c12").pack(pady=10)
        
        tk.Label(info_frame, text=f"Nom d'utilisateur: {username}", font=("Arial", 11),
                bg="#34495e", fg="#ecf0f1").pack(pady=5)
        
        tk.Label(info_frame, text=f"Type de compte: Standard", font=("Arial", 11),
                bg="#34495e", fg="#ecf0f1").pack(pady=5)
        
        tk.Label(info_frame, text=f"Statut: ✓ Actif", font=("Arial", 11),
                bg="#34495e", fg="#ecf0f1").pack(pady=5, padx=10)
        
        # Bouton de déconnexion
        logout_btn = tk.Button(frame, text="Déconnexion", font=("Arial", 12, "bold"),
                              bg="#e74c3c", fg="white", width=20, command=self.show_login_screen)
        logout_btn.pack(pady=20)
        
    def run(self):
        """Lance l'application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = BankApp()
    app.run()