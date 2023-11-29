import sys
import json
import ast
import astexport.export


class Pattern:
    def __init__(self, name, sources, sanitizers, sinks):
        self.name = name  # Vulnerability Name
        self.sources = []  # Sources
        self.sanitizers = []  # Sanitizers
        self.sinks = []  # Sink Names

        if isinstance(sources, str):
            self.sources.append(sources)
        else:
            self.sources.extend(sources)

        if isinstance(sanitizers, str):
            self.sanitizers.append(sanitizers)
        else:
            self.sanitizers.extend(sanitizers)

        if isinstance(sinks, str):
            self.sinks.append(sinks)
        else:
            self.sinks.extend(sinks)

    def get_name(self):
        return self.name

    def get_sources(self):
        return self.sources

    def get_sanitizers(self):
        return self.sanitizers

    def get_sinks(self):
        return self.sinks

    def test_string(self, string):
        if string in self.sources:
            print("The string " + string + " is a source of this pattern.")
        if string in self.sanitizers:
            print("The string " + string + " is a sanitizer of this pattern.")
        if string in self.sinks:
            print("The string '" + string + "' is a sink of this pattern.")


class Label:
    def __init__(self):
        self.sources_sanitizers = {}

    def add_sources(self, source):
        self.sources_sanitizers[source] = []

    def add_sanitizer(self, source, sanitizer):
        if source in self.sources_sanitizers:
            self.sources_sanitizers[source].append(sanitizer)
        else:
            raise ValueError(f"Source {source} does not exist")

    def get_sources(self):
        return self.sources_sanitizers

    def get_sanitizers(self, source):
        return self.sources_sanitizers[source]

    def combine(self, other):
        new_label = Label()
        new_label.sources_sanitizers = {**self.sources_sanitizers, **other.sources_sanitizers}

        return new_label


class MultiLabel:
    def __init__(self, label=None, pattern=None):
        self.labels_patterns = {}
        if label is not None:
            if not isinstance(label, Label):
                raise ValueError(f"Label {label} does not exist")
            elif not isinstance(pattern, Pattern):
                raise ValueError(f"Pattern {pattern} does not exist")
            else:
                self.labels_patterns[label] = [pattern]

    def add(self, label, pattern):
        if label not in self.labels_patterns:
            self.labels_patterns[label] = []

        self.labels_patterns[label].append(pattern)

    def get_labels(self, pattern):
        labels = []
        for label, patterns in self.labels_patterns.items():
            if pattern in patterns:
                labels.append(label)
        return labels

    def get_patterns(self, label):
        return self.labels_patterns.get(label, [])

    def combine(self, other):
        combined = MultiLabel()

        for label, patterns in self.labels_patterns.items():
            combined.labels_patterns[label] = list(patterns)

        for label, patterns in other.labels_patterns.items():
            if label in combined.labels_patterns:
                combined.labels_patterns[label].extend(patterns)
            else:
                combined.labels_patterns[label] = list(patterns)

        return combined


class Policy:
    def __init__(self, patterns):
        self.patterns = []
        if isinstance(patterns, Pattern):
            self.patterns = [patterns, ]
        elif list(map(type, patterns)) == [Pattern] or tuple(map(type, patterns)) == [Pattern]:
            self.patterns = [].extend(patterns)
        else:
            raise ValueError(f"Patterns {patterns} invalid")

    def get_vulnerabilities(self):
        return [pattern.get_name() for pattern in self.patterns]

    def get_sources(self, source):
        return [pattern.get_name() for pattern in self.patterns if source in pattern.get_sources()]

    def get_sanitizers(self, name):
        return [pattern.get_name() for pattern in self.patterns if name in pattern.get_sanitizers()]

    def get_sinks(self, name):
        return [pattern.get_name() for pattern in self.patterns if name in pattern.get_sinks()]

    def find_illegal_flows(self, name, multilabel):
        illegal_multilabels = MultiLabel()
        for pattern in multilabel.get_patterns():
            if pattern in self.patterns:
                if name in pattern.get_sinks():
                    illegal_multilabels.add(label="illegal", pattern=pattern)
        return illegal_multilabels


class MultiLabelling:
    def __init__(self, patterns):
        self.map = {}

    def get_multilabel(self, name):
        self.map.get(name)

    def update_multilabel(self, name, multilabel):
        if self.map.get(name) is None:
            self.map[name] = multilabel
        else:
            self.map[name] = multilabel


class Vulnerabilities:
    def __init__(self):
        self.vuln = []

    def analyze(self, multilabel, name):
        for pattern in multilabel.get_patterns():
            pattern.get_sources()
            self.vuln.append(pattern)


def read_slice(filename):
    # Read slice code from file
    with open(filename) as f:
        code = f.read()

    # Validate slice code format
    if code is None:
        print("Invalid slice format")
        exit(1)

    return astexport.export.export_dict(ast.parse(code))


def read_patterns(filename):
    # Read patterns from JSON file
    try:
        with open(filename) as f:
            patterns = json.load(f)
    except ValueError:
        print("Invalid patterns JSON format")
        exit(1)

    # Validate patterns format
    if patterns is None:
        print("Invalid patterns format")
        exit(1)

    return patterns


def analyze(dicts, patterns):
    # Using the same terms as in Python Parser the mandatory
    # constructs are those associated with nodes of type
    # ::Expressions::
    # Constant
    # Name
    # BinOp, UnaryOp
    # BoolOp, Compare
    # Call
    # Attribute
    # ::Statements::
    # Expr
    # Assign
    # If
    # While

    # < OUTPUT >: := [ < VULNERABILITIES >]
    # < VULNERABILITIES > := "none" | < VULNERABILITY > | < VULNERABILITY >, < VULNERABILITIES >
    # < VULNERABILITY >: := {"vulnerability": "<STRING>",
    #                        "source": ("<STRING>", < INT >)
    #                        "sink": ("<STRING>", < INT >),
    #                        "unsanitized_flows": < YESNO >,
    # "sanitized_flows": [ < FLOWS >]}
    # < YESNO >: := "yes" | "no"
    # < FLOWS >: := "none" | < FLOW > | < FLOW >, < FLOWS >
    # < FLOW >: := [ < SANITIZERS >]
    # < SANITIZERS >: := (< STRING >, < INT >) | (< STRING >, < INT >), < SANITIZERS >
    return 0


def generate_output(vulnerabilities):
    output = []

    for v in vulnerabilities:
        vulnerability = {
            "vulnerability": v["name"],
            "source": (v["source"], v["source_line"]),
            "sink": (v["sink"], v["sink_line"]),
            "unsanitized_flows": v["sink_unsanitized"],
            "sanitized_flows": v["sink_sanitized"]
        }

        output.append(vulnerability)

    return output


def write_output(output, slice_filename):
    # Generate output filename
    output_filename = f"./output/{slice_filename}.output.json"

    # Write results to output file
    with open(output_filename, "w") as f:
        json.dump(output, f)


def main():
    if len(sys.argv) != 3:
        print("Usage: python analyzer.py slice_file patterns_file")
        sys.exit(1)

    slice_filename = sys.argv[1]
    patterns_filename = sys.argv[2]

    ast_dict = read_slice(slice_filename)
    # --------------DEBUG CODE-------------
    # json = json.dumps(code)
    # print(json)

    patterns = read_patterns(patterns_filename)

    results = analyze(ast_dict, patterns)

    generate_output(results)
    write_output(results, slice_filename)


if __name__ == "__main__":
    main()
