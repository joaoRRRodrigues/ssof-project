# Lab 1
class Pattern:
	def __init__(self, vulnerability: str, sources: list, sanitizers: list, sinks: list, implicit: str):
		self.vulnerability = vulnerability
		self.sources = sources
		self.sanitizers = sanitizers
		self.sinks = sinks
		self.implicit = True if implicit == "yes" else False

	### Selectors
	def get_vulnerability(self):
		return self.vulnerability

	def get_sources(self):
		return self.sources

	def get_sanitizers(self):
		return self.sanitizers

	def get_sinks(self):
		return self.sinks
	
	def is_implicit(self):
		return self.implicit

	### Verifiers
	def is_source(self, name: str):
		return name in self.sources

	def is_sanitizer(self, name: str):
		return name in self.sanitizers

	def is_sink(self, name: str):
		return name in self.sinks
	
	def test_component(self, name: str):
		if self.is_source(name):
			return "source"
		elif self.is_sanitizer(name):
			return "sanitizer"
		elif self.is_sink(name):
			return "sink"
		else:
			return None
		
	### Print
	def __str__(self):
		return "Pattern"
