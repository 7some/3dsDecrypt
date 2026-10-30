import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from Cryptodome.Cipher import AES
import threading

class ThreeDS_Decryptor:
    """Decrypts 3DS ROM files using AES keys from a file."""
    
    def __init__(self):
        self.keys = {}
    
    def load_keys(self, keys_file):
        """Load AES keys from the keys file."""
        self.keys = {}
        if not os.path.exists(keys_file):
            raise FileNotFoundError(f"Keys file not found: {keys_file}")
        
        with open(keys_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse key format: name=hexvalue or name: hexvalue
                if '=' in line:
                    name, key_hex = line.split('=', 1)
                elif ':' in line:
                    name, key_hex = line.split(':', 1)
                else:
                    continue
                
                name = name.strip()
                key_hex = key_hex.strip()
                
                try:
                    self.keys[name] = bytes.fromhex(key_hex)
                except ValueError:
                    print(f"Warning: Invalid hex value for key '{name}'")
        
        return len(self.keys) > 0
    
    def is_valid_decryption(self, data, chunk_size=16):
        """
        Validate if decrypted data looks reasonable.
        3DS ROMs typically have a specific header structure.
        """
        # Check for common 3DS ROM magic bytes or patterns
        # This is a basic heuristic - adjust as needed
        if len(data) < 256:
            return False
        
        # Check if the data contains mostly non-null bytes (indicates valid decryption)
        non_null_count = sum(1 for byte in data[:256] if byte != 0x00)
        
        # If more than 50% of the header is non-null, likely valid
        return non_null_count > 128
    
    def try_decrypt_with_all_keys(self, rom_path, output_path, progress_callback=None):
        """
        Try to decrypt ROM with all available keys until one works.
        
        Args:
            rom_path: Path to encrypted ROM
            output_path: Path to save decrypted ROM
            progress_callback: Function to call with progress updates
        
        Returns:
            tuple: (success: bool, key_name: str, message: str)
        """
        if not os.path.exists(rom_path):
            return False, None, f"ROM file not found: {rom_path}"
        
        if not self.keys:
            return False, None, "No keys loaded"
        
        rom_size = os.path.getsize(rom_path)
        iv = b'\x00' * 16
        
        # Try each key
        for key_name, key in self.keys.items():
            try:
                if progress_callback:
                    progress_callback(f"Trying key: {key_name}...", 0)
                
                # Read and decrypt the ROM
                cipher = AES.new(key, AES.MODE_CBC, iv)
                chunk_size = 1024 * 1024  # 1MB chunks
                decrypted_data = b''
                total_read = 0
                
                with open(rom_path, 'rb') as infile:
                    with open(output_path, 'wb') as outfile:
                        while True:
                            chunk = infile.read(chunk_size)
                            if not chunk:
                                break
                            
                            decrypted_chunk = cipher.decrypt(chunk)
                            outfile.write(decrypted_chunk)
                            total_read += len(chunk)
                            
                            # Store first chunk for validation
                            if not decrypted_data:
                                decrypted_data = decrypted_chunk
                            
                            # Update progress
                            if progress_callback:
                                progress = (total_read / rom_size) * 100
                                progress_callback(f"Trying key: {key_name}...", progress)
                
                # Validate the decrypted data
                if self.is_valid_decryption(decrypted_data):
                    return True, key_name, f"Successfully decrypted with key: {key_name}"
                else:
                    # Invalid decryption, delete the output file and try next key
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    if progress_callback:
                        progress_callback(f"Key {key_name} failed validation, trying next...", 0)
            
            except Exception as e:
                # Error with this key, try next
                if os.path.exists(output_path):
                    os.remove(output_path)
                continue
        
        return False, None, "No valid key found for this ROM"


class DecrypterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("3DS ROM Decryptor")
        self.root.geometry("600x500")
        
        self.decryptor = ThreeDS_Decryptor()
        self.keys_file = None
        self.rom_file = None
        self.rom_format = tk.StringVar(value="3ds")
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create GUI elements."""
        
        # Title
        title = tk.Label(self.root, text="3DS ROM Decryptor", font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Keys file selection
        keys_frame = tk.Frame(self.root)
        keys_frame.pack(pady=10, padx=10, fill="x")
        
        tk.Label(keys_frame, text="AES Keys File:", font=("Arial", 10)).pack(side="left")
        self.keys_label = tk.Label(keys_frame, text="No file selected", fg="gray")
        self.keys_label.pack(side="left", padx=10)
        
        tk.Button(keys_frame, text="Browse", command=self.select_keys_file).pack(side="right")
        
        # ROM file selection
        rom_frame = tk.Frame(self.root)
        rom_frame.pack(pady=10, padx=10, fill="x")
        
        tk.Label(rom_frame, text="ROM File:", font=("Arial", 10)).pack(side="left")
        self.rom_label = tk.Label(rom_frame, text="No file selected", fg="gray")
        self.rom_label.pack(side="left", padx=10)
        
        tk.Button(rom_frame, text="Browse", command=self.select_rom_file).pack(side="right")
        
        # ROM format selection
        format_frame = tk.Frame(self.root)
        format_frame.pack(pady=10, padx=10, fill="x")
        
        tk.Label(format_frame, text="ROM Format:", font=("Arial", 10)).pack(side="left")
        tk.Radiobutton(format_frame, text=".3ds", variable=self.rom_format, value="3ds").pack(side="left", padx=5)
        tk.Radiobutton(format_frame, text=".cci", variable=self.rom_format, value="cci").pack(side="left", padx=5)
        
        # Progress bar
        progress_frame = tk.Frame(self.root)
        progress_frame.pack(pady=15, padx=10, fill="x")
        
        tk.Label(progress_frame, text="Progress:", font=("Arial", 10)).pack(anchor="w")
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate', length=500)
        self.progress_bar.pack(fill="x", pady=5)
        
        self.status_label = tk.Label(progress_frame, text="Ready", fg="black", font=("Arial", 9))
        self.status_label.pack(anchor="w")
        
        # Decrypt button
        self.decrypt_button = tk.Button(self.root, text="Decrypt ROM", command=self.decrypt_rom, 
                                        font=("Arial", 12, "bold"), bg="green", fg="white", padx=20, pady=10)
        self.decrypt_button.pack(pady=20)
    
    def select_keys_file(self):
        """Open file dialog to select keys file."""
        file_path = filedialog.askopenfilename(
            title="Select AES Keys File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            self.keys_file = file_path
            self.keys_label.config(text=os.path.basename(file_path), fg="black")
            
            # Try to load keys
            try:
                if self.decryptor.load_keys(file_path):
                    self.status_label.config(text=f"Loaded {len(self.decryptor.keys)} key(s)", fg="green")
                else:
                    self.status_label.config(text="No valid keys found in file", fg="red")
            except Exception as e:
                self.status_label.config(text=f"Error loading keys: {e}", fg="red")
    
    def select_rom_file(self):
        """Open file dialog to select ROM file."""
        file_path = filedialog.askopenfilename(
            title="Select ROM File",
            filetypes=[("3DS/CCI files", "*.3ds *.cci"), ("All files", "*.*")]
        )
        
        if file_path:
            self.rom_file = file_path
            self.rom_label.config(text=os.path.basename(file_path), fg="black")
    
    def update_progress(self, message, progress):
        """Update progress bar and status."""
        self.status_label.config(text=message, fg="blue")
        self.progress_bar['value'] = progress
        self.root.update_idletasks()
    
    def decrypt_rom(self):
        """Decrypt the ROM using auto-detected key."""
        # Validate inputs
        if not self.keys_file:
            messagebox.showerror("Error", "Please select an AES keys file")
            return
        
        if not self.rom_file:
            messagebox.showerror("Error", "Please select a ROM file")
            return
        
        # Generate output path
        rom_dir = os.path.dirname(self.rom_file)
        rom_ext = self.rom_format.get()
        output_path = os.path.join(rom_dir, f"game_decrypted.{rom_ext}")
        
        # Disable button during decryption
        self.decrypt_button.config(state="disabled")
        
        # Run decryption in a separate thread
        def decrypt_thread():
            success, key_name, message = self.decryptor.try_decrypt_with_all_keys(
                self.rom_file, output_path, self.update_progress
            )
            
            # Update UI on main thread
            self.root.after(0, lambda: self.decryption_complete(success, message, output_path))
        
        thread = threading.Thread(target=decrypt_thread, daemon=True)
        thread.start()
    
    def decryption_complete(self, success, message, output_path):
        """Handle decryption completion."""
        self.decrypt_button.config(state="normal")
        
        if success:
            self.progress_bar['value'] = 100
            self.status_label.config(text=message, fg="green")
            messagebox.showinfo("Success", f"{message}\n\nOutput: {output_path}")
        else:
            self.progress_bar['value'] = 0
            self.status_label.config(text=message, fg="red")
            messagebox.showerror("Error", message)


if __name__ == "__main__":
    root = tk.Tk()
    gui = DecrypterGUI(root)
    root.mainloop()

