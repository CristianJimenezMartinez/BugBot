import asyncio
import json
import os
import tempfile
import logging
from typing import List
from core.config import Config

logger = logging.getLogger("BugBot.Ripper.AST")

class ASTRipper:
    """Motor atómico para análisis AST vía subproceso Node.js."""
    
    def __init__(self, semaphore: asyncio.Semaphore):
        self.semaphore = semaphore
        self.node_parser_script = os.path.join(Config.BASE_DIR, "core", "js_parser", "ast_ripper.js")

    async def rip(self, js_content: str) -> List[str]:
        """Llama al AST Parser de Node.js sobre contenido JS."""
        if not os.path.exists(self.node_parser_script):
            logger.debug(f"[Ripper] AST Parser no encontrado en {self.node_parser_script}")
            return []
            
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".js", mode='w', encoding='utf-8') as tf:
                tf.write(js_content)
                temp_path = tf.name

            async with self.semaphore:
                process = await asyncio.create_subprocess_exec(
                    "node", self.node_parser_script, temp_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0 and stdout:
                    data = json.loads(stdout.decode('utf-8', errors='ignore'))
                    return data.get("routes", [])
                else:
                    err_msg = stderr.decode('utf-8', errors='ignore')
                    if err_msg: logger.debug(f"[Ripper Node Error] {err_msg}")
                    
        except Exception as e:
            logger.error(f"[Ripper Exception] {e}")
        finally:
            if temp_path and os.path.exists(temp_path):
                try: os.unlink(temp_path)
                except: pass
            
        return []
