class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    
    @staticmethod
    def ok(text): return f"{Colors.GREEN}✅ {text}{Colors.RESET}"
    @staticmethod
    def err(text): return f"{Colors.RED}❌ {text}{Colors.RESET}"
    @staticmethod
    def warn(text): return f"{Colors.YELLOW}⚠️ {text}{Colors.RESET}"
    @staticmethod
    def info(text): return f"{Colors.CYAN}ℹ️ {text}{Colors.RESET}"
