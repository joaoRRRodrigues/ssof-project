from multi_label import MultiLabel


# Lab 2
class MultiLabelling:
	def __init__(self):
		self.mapping = dict()

	def get_multilabel_by_variable(self, variable_name: str):
		self.mapping.get(variable_name)

	def update_mapping(self, variable_name: str, multilabel: MultiLabel):
		self.mapping[variable_name] = multilabel
	
	### Print
	def __str__(self):
		return "MultiLabelling"
