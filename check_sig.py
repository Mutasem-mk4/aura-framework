import inspect
from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer

print(f"File: {inspect.getfile(StatefulLogicFuzzer)}")
print(f"Init Signature: {inspect.signature(StatefulLogicFuzzer.__init__)}")
