import argparse
from scanner import VirusScanner

def interactive():
    scanner = VirusScanner()
    
    while True:
        print("\n" + "="*40)
        print("VirusTotal Scanner")
        print("="*40)
        print("1. Scan file")
        print("2. Scan URL")
        print("3. Scan by hash")
        print("4. Exit")
        
        choice = input("\nChoose (1-4): ").strip()
        
        if choice == "1":
            path = input("File path: ").strip()
            scanner.scan_file(path)
        elif choice == "2":
            url = input("URL: ").strip()
            scanner.scan_url(url)
        elif choice == "3":
            hash_val = input("SHA-256 hash: ").strip()
            scanner.scan_hash(hash_val)
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice")

def main():
    parser = argparse.ArgumentParser(description="VirusTotal Scanner")
    parser.add_argument("--file", help="Scan file")
    parser.add_argument("--url", help="Scan URL")
    parser.add_argument("--hash", help="Scan by hash")
    
    args = parser.parse_args()
    
    try:
        scanner = VirusScanner()
        
        if args.file:
            scanner.scan_file(args.file)
        elif args.url:
            scanner.scan_url(args.url)
        elif args.hash:
            scanner.scan_hash(args.hash)
        else:
            interactive()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
