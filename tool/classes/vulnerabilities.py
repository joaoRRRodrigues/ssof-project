# Lab 2
from multi_label import MultiLabel

class Vulnerability:
	def __init__(self, name: str, source: list, sink: list, unsanitized_flows: bool, sanitized_flows: list):
		self.params = {
			"vulnerability": name,
			"source": source,
			"sink": sink,
			"unsanitized_flows": "yes" if unsanitized_flows is True else "no",
			"sanitized_flows": sanitized_flows
		}

	### Print
	""" def __str__(self):
		return "Vulnerability" """

class Vulnerabilities:
	def __init__(self):
		self.vulns = dict()

	def add_vulnerability(self, resource_name: str, multilabel: 'MultiLabel'):
		for vulnerability_name, label in multilabel.get_patterns_labels().items():
			for source, sanitizer in label.items():
				if vulnerability_name not in self.vulns:
					self.vulns[vulnerability_name] = list()
				
				size = len(self.vulns[vulnerability_name])
				name = vulnerability_name + "_" + str(size+1)

				# TODO - finish the unsanitized flows part
				new_vulnerability = Vulnerability(name, source, resource_name, False, sanitizer)

				self.vulns[vulnerability_name].append(new_vulnerability)

	### Print
	def __str__(self):
		return "Vulnerabilities"
