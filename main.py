from core.installation import Install

Install()   # Run installation if needed

from core.base import Base
from core.parser import Parser
from core.interceptprocess import InterceptProcess
import time



BaseInstance = Base()
ParserInstance = Parser(BaseInstance)
IProcInstance = InterceptProcess(ParserInstance, BaseInstance)


try:

    while BaseInstance.hb_active:
        time.sleep(5)

finally:
    for subprocess in IProcInstance.subprocess:
        print(f'Terminate subprocess {subprocess}')
        subprocess.terminate()
