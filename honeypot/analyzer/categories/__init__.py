#!/usr/bin/env python3

import os
import logging
import importlib
import inspect
import re
import pkgutil
from abc import ABC, abstractmethod
from pathlib import Path

# Configurare logging
logger = logging.getLogger('honeypot.analyzer')

class AttackCategory(ABC):  
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.patterns = []
        
    @abstractmethod
    def match(self, command):
 
        pass
    
    def get_severity(self, command):
        # Implementare implicită, poate fi suprascrisă de clasele derivate
        return 5
    
    def get_name(self):
        return self.name

def get_all_categories():
    category_classes = []
    
    try:
        # Obținem calea către acest modul
        package_dir = Path(__file__).parent
        
        # Obținem numele pachetului
        package_name = __name__
        
        # Listăm toate modulele Python din directorul categoriilor
        module_names = []
        
        for _, module_name, is_pkg in pkgutil.iter_modules([str(package_dir)]):
            # Excludem modulele care încep cu underscore (private)
            if not module_name.startswith('_') and not is_pkg:
                module_names.append(module_name)
        
        # Încărcăm fiecare modul și găsim clasele de categorii
        for module_name in module_names:
            try:
                # Construim numele complet al modulului
                full_module_name = f"{package_name}.{module_name}"
                
                # Încărcăm modulul
                module = importlib.import_module(full_module_name)
                
                # Găsim clasele care moștenesc AttackCategory
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, AttackCategory) and 
                        obj != AttackCategory):
                        category_classes.append(obj)
                        logger.debug(f"Clasă de categorie găsită: {name}")
                
            except ImportError as e:
                logger.error(f"Nu s-a putut importa modulul {module_name}: {str(e)}")
            except Exception as e:
                logger.error(f"Eroare la procesarea modulului {module_name}: {str(e)}")
        
        logger.info(f"Au fost găsite {len(category_classes)} clase de categorii")
        
    except Exception as e:
        logger.error(f"Eroare la scanarea categoriilor: {str(e)}")
    
    return category_classes