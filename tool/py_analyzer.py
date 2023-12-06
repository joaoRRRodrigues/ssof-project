import sys
import json
import ast
import astexport.export
import os

def read_slice(filename):
	# Read slice code from file
	with open(filename, "r") as f:
		code = f.read()

	# Validate slice code format
	if code is None:
		print("Error: Invalid slice format")
		exit(1)



	a = astexport.export.export_dict(ast.parse(code))
	b = json.dumps(a)
	print(b)
	return astexport.export.export_dict(ast.parse(code))


def read_patterns(filename):
	# Read patterns from JSON file
	try:
		with open(filename, "r") as f:
			patterns = json.load(f)
			#print(patterns)
			a = patterns[0].get('vulnerability')
			print(a)
	except ValueError:
		print("Error: Invalid patterns JSON format")
		exit(1)

	# Validate patterns format
	if patterns is None:
		print("Error: Invalid patterns format")
		exit(1)

	return patterns


def analyze(dicts, patterns):
	# Using the same terms as in Python Parser the mandatory
	# constructs are those associated with nodes of type
	#           
	#           ::Expressions::
	# Constant
	# Name
	# BinOp, UnaryOp
	# BoolOp, Compare
	# Call
	# Attribute
	#           ::Statements::
	# Expr
	# Assign
	# If
	# 1

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


def generate_output(vulnerabilities: dict):

	output = []

	for vulnerability_name, vulns_list in vulnerabilities.items():
		for vulnerability in vulns_list:
			output.append(vulnerability)
	return output


def write_output(output, slice_filename):
	# Generate output filename
	output_filename = f"./output/{slice_filename}.output.json"

	# Write results to output file
	with open(output_filename, "w") as f:
		json.dump(output, f)

def input_validation(slice_filename, patterns_filename):
	if not (os.path.exists(slice_filename)):
		print(f"Error: File {slice_filename} does not exist")
		exit(1)
	elif not (os.path.exists(patterns_filename)):
		print(f"Error: File {patterns_filename} does not exist")
		exit(1)
	else:
		print("Success!")
		


def main():
	if len(sys.argv) != 3:
		print("Usage: python analyzer.py slice_file patterns_file")
		sys.exit(1)

	slice_filename = sys.argv[1]
	patterns_filename = sys.argv[2]

	input_validation(slice_filename, patterns_filename)

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
