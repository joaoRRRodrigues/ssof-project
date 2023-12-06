# Lab 1
from label import Label
from pattern import Pattern


class MultiLabel:
	def __init__(self, vulnerability_names: list):
		# Create dictionary with each vulnerability name as keys but empty labels as values
		self.patterns_labels = {key: Label() for key in vulnerability_names}

	def add_label(self, vulnerability_name: str, label: Label):
		self.patterns_labels[vulnerability_name] = label

	# TODO, assumimos que a verificação se é source da pattern foi feita anteriormente?
	def add_source_to_label(self, source: str, vulnerability_name: str):
		label = self.patterns_labels.get(vulnerability_name)
		label.add_source(source)
		
	# TODO, recebe source? assumimos que a verificação se é sanitizer da pattern foi feita anteriormente?
	def add_sanitizer_to_label(self, source: str, sanitizer: str, vulnerability_name: str):
		label = self.patterns_labels.get(vulnerability_name)
		label.add_sanitizer(source, sanitizer)

	def get_patterns_labels(self):
		return self.patterns_labels
	
	def get_label_by_pattern(self, vulnerability_name: str):
		return self.patterns_labels.get(vulnerability_name)
	
	# TODO
	def combine_multilabels(self, other_multilabel: 'MultiLabel'):
		new_multilabel = MultiLabel()

		for vulnerability_name, label in self.patterns_labels.items():
			other_label = other_multilabel.get_label_by_pattern[vulnerability_name]
			combined_label = label.combine_labels(other_label)
			new_multilabel.add_label(vulnerability_name, combined_label)

		return new_multilabel
	
	### Print
	def __str__(self):
		return "MultiLabel"
