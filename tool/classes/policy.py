# Lab 2
from pattern import Pattern
from multi_label import MultiLabel


class Policy:
	def __init__(self, patterns: list):
		self.patterns = patterns	# List of all the patterns

	def get_vulnerabilities_by_source(self, source: str):
		return [pattern.get_vulnerability() for pattern in self.patterns if source in pattern.get_sources()]

	def get_vulnerabilities_by_sanitizer(self, sanitizer: str):
		return [pattern.get_vulnerability() for pattern in self.patterns if sanitizer in pattern.get_sanitizers()]

	def get_vulnerabilities_by_sink(self, sink: str):
		return [pattern.get_vulnerability() for pattern in self.patterns if sink in pattern.get_sinks()]

	def find_illegal_flows(self, resource_name: str, multilabel: 'MultiLabel'):
		illegal_multilabel = MultiLabel()

		for vulnerability_name, label in multilabel.get_patterns_labels().items():
			pattern = next((pattern for pattern in self.patterns if pattern.get_vulnerability() == vulnerability_name), None)

			if pattern is not None and resource_name in pattern.get_sinks() and bool(label): # TODO, bool(label) retorna false se estiver vazio?
				illegal_multilabel.add_label(vulnerability_name, label)
		
		return illegal_multilabel

	### Print
	def __str__(self):
		return "Policy"
