# Lab 1
class Label:
	def __init__(self):
		self.sources_sanitizers = dict()

	def add_source(self, source: str):
		self.sources_sanitizers[source] = []

	# TODO, recebe source?
	def add_sanitizer(self, source: str, sanitizer: str):
		if source in self.sources_sanitizers:
			self.sources_sanitizers[source].append(sanitizer)
		else:
			raise ValueError(f"Source {source} does not exist in the Label")

	def get_sources_sanitizers(self):
		return self.sources_sanitizers

	def get_sanitizers_by_source(self, source: str):
		return self.sources_sanitizers.get(source)

	def combine_labels(self, other_label: 'Label'):
		new_label = Label()
		new_label.sources_sanitizers = {**self.sources_sanitizers, **other_label.sources_sanitizers}

		return new_label

	### Print
	def __str__(self):
		return "Label"


