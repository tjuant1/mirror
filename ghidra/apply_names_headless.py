# -*- coding: utf-8 -*-
import json

processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED

def get_addr(addr):
	return baseAddress.add(addr)

def set_name(addr, name):
	name = name.replace(' ', '-')
	try:
		createLabel(addr, name, True, USER_DEFINED)
	except:
		print("set_name failed for " + name)

def make_function(start):
	func = getFunctionAt(start)
	if func is None:
		try:
			createFunction(start, None)
		except:
			pass

SCRIPT_JSON_PATH = "C:/QA/apps/mirror/il2cppdumper/extracted/output/script.json"
data = json.loads(open(SCRIPT_JSON_PATH, 'rb').read().decode('utf-8'))

if "ScriptMethod" in data and "ScriptMethod" in processFields:
	scriptMethods = data["ScriptMethod"]
	monitor.initialize(len(scriptMethods))
	monitor.setMessage("Methods")
	for scriptMethod in scriptMethods:
		addr = get_addr(scriptMethod["Address"])
		name = scriptMethod["Name"].encode("utf-8")
		set_name(addr, name)
		monitor.incrementProgress(1)

if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
	scriptMetadatas = data["ScriptMetadata"]
	monitor.initialize(len(scriptMetadatas))
	monitor.setMessage("Metadata")
	for scriptMetadata in scriptMetadatas:
		addr = get_addr(scriptMetadata["Address"])
		name = scriptMetadata["Name"].encode("utf-8")
		set_name(addr, name)
		setEOLComment(addr, name)
		monitor.incrementProgress(1)

if "Addresses" in data and "Addresses" in processFields:
	addresses = data["Addresses"]
	monitor.initialize(len(addresses))
	monitor.setMessage("Addresses")
	for index in range(len(addresses) - 1):
		start = get_addr(addresses[index])
		make_function(start)
		monitor.incrementProgress(1)

print('Script finished!')
