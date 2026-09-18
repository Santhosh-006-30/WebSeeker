import logging
import os
import sys

def setup_logger(name="WebSeekerPro"):
    """
    Sets up a centralized, professional logger.
    Logs to both the console (with rich formatting if available) and a file.
    """
    logger = logging.getLogger(name)
    
    # Only setup if not already configured to avoid duplicate handlers
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # Formatter for file (detailed JSON or standard format)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        
        # Ensure log directory exists
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        # File Handler
        file_handler = logging.FileHandler(os.path.join(log_dir, "webseeker.log"))
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Console Handler (try to use Rich, fallback to standard)
        try:
            from rich.logging import RichHandler
            console_handler = RichHandler(rich_tracebacks=True, markup=True)
            console_formatter = logging.Formatter("%(message)s")
        except ImportError:
            console_handler = logging.StreamHandler(sys.stdout)
            console_formatter = logging.Formatter('%(levelname)s: %(message)s')
            
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger

# Global logger instance
log = setup_logger()
