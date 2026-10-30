import os
from Cryptodome.Cipher import AES

class ThreeDS_Decryptor:
    """Decrypts 3DS ROM files using AES keys from a file."""
    
    def __init__(self, keys_file="aes_keys.txt"):
        """Initialize with path to AES keys file."""
        self.keys_file = keys_file
        self.keys = self._load_keys()
    
    def _load_keys(self):
        """Load AES keys from the keys file."""
        keys = {}
        
        if not os.path.exists(self.keys_file):
            raise FileNotFoundError(f"Keys file not found: {self.keys_file}")
        
        with open(self.keys_file, 'r') as f:
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
                    keys[name] = bytes.fromhex(key_hex)
                except ValueError:
                    print(f"Warning: Invalid hex value for key '{name}'")
        
        return keys
    
    def decrypt_rom(self, rom_path, output_path, key):
        """
        Decrypt a 3DS ROM file using CBC mode.
        
        Args:
            rom_path: Path to encrypted ROM
            output_path: Path to save decrypted ROM
            key: AES key (bytes)
        
        Returns:
            bool: True if successful, False otherwise
        """
        
        if not os.path.exists(rom_path):
            print(f"Error: ROM file not found: {rom_path}")
            return False
        
        try:
            rom_size = os.path.getsize(rom_path)
            print(f"\nDecrypting {rom_path}...")
            print(f"ROM size: {rom_size / (1024*1024):.2f} MB")
            print(f"Key: {key.hex().upper()}")
            
            # IV is typically zeros for 3DS
            iv = b'\x00' * 16
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Read and decrypt in chunks
            chunk_size = 1024 * 1024  # 1MB chunks
            decrypted_size = 0
            
            with open(rom_path, 'rb') as infile:
                with open(output_path, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunk_size)
                        if not chunk:
                            break
                        
                        decrypted_chunk = cipher.decrypt(chunk)
                        outfile.write(decrypted_chunk)
                        decrypted_size += len(decrypted_chunk)
                        
                        # Progress indicator
                        progress = (decrypted_size / rom_size) * 100
                        print(f"Progress: {progress:.1f}%", end='\r')
            
            print(f"\n✓ Successfully decrypted to: {output_path}")
            return True
        
        except Exception as e:
            print(f"✗ Error during decryption: {e}")
            return False


def get_rom_format():
    """Ask user for ROM format and return the corresponding file path and output name."""
    while True:
        user_input = input("\nWhat is your ROM format? (3ds/cci): ").strip().lower()
        
        if user_input == "3ds":
            rom_path = "game.3ds"
            output_path = "game_decrypted.3ds"
            format_type = "3DS"
            break
        elif user_input == "cci":
            rom_path = "game.cci"
            output_path = "game_decrypted.cci"
            format_type = "CCI"
            break
        else:
            print("Invalid input. Please type '3ds' or 'cci'.")
            continue
    
    return rom_path, output_path, format_type


if __name__ == "__main__":
    try:
        # Initialize decryptor
        decryptor = ThreeDS_Decryptor("aes_keys.txt")
        
        print("=" * 50)
        print("3DS ROM Decryptor")
        print("=" * 50)
        print(f"\nLoaded {len(decryptor.keys)} key(s) from aes_keys.txt\n")
        
        # Use first available key (most common case)
        if not decryptor.keys:
            print("Error: No keys found in aes_keys.txt")
        else:
            key_name = list(decryptor.keys.keys())[0]
            key = decryptor.keys[key_name]
            
            # Ask user for ROM format
            rom_path, output_path, format_type = get_rom_format()
            
            print(f"Using key: {key_name}")
            print(f"ROM format: {format_type}")
            
            # Check if ROM file exists
            if not os.path.exists(rom_path):
                print(f"\nError: {rom_path} not found in the current directory!")
            else:
                # Decrypt
                success = decryptor.decrypt_rom(rom_path, output_path, key)
                
                print("\n" + "=" * 50)
                if success:
                    print("Decryption complete!")
                else:
                    print("Decryption failed!")
                print("=" * 50)
    
    except FileNotFoundError as e:
        print(f"Setup Error: {e}")
        print("\nMake sure you have aes_keys.txt in the same folder with your AES keys.")

