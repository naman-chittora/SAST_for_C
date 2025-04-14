import re
import sys
import json

class CSASTAnalyzer:
    def __init__(self, code_lines):
        self.lines = code_lines
        self.issues = []
        self.declared_vars = {}
        self.used_vars = set()

    # Main analysis function to run all checks
    def analyze(self):
        for lineno, line in enumerate(self.lines, start=1):
            self.check_dangerous_functions(line, lineno)
            self.check_integer_arithmetic(line, lineno)
            self.track_variable_declarations(line, lineno)
            self.track_variable_usage(line)
        # for unused variables
        self.check_unused_variables()

    # for dangerous C functions
    def check_dangerous_functions(self, line, lineno):
        if re.search(r'\b(gets|strcpy|strcat|sprintf|scanf|system)\s*\(', line):
            func = re.findall(r'\b(gets|strcpy|strcat|sprintf|scanf|system)\b', line)[0]
            self.issues.append((lineno, f"Use of dangerous function '{func}'", line.strip(), "High"))

    # for integer overflow/underflow
    def check_integer_arithmetic(self, line, lineno):
        if re.search(r'\b\w+\s*=\s*[^;]*[\+\-\*/][^;]*;', line):
            self.issues.append((lineno, "Potential integer overflow/underflow in arithmetic operation", line.strip(), "Medium"))

    def track_variable_declarations(self, line, lineno):
        match = re.match(r'\s*(int|char|float|double)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', line)
        if match:
            var = match.group(2)
            self.declared_vars[var] = lineno

    
    def track_variable_usage(self, line):
        tokens = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', line)
        for token in tokens:
            self.used_vars.add(token)

    # find and report unused variables
    def check_unused_variables(self):
        unused = set(self.declared_vars.keys()) - self.used_vars
        for var in unused:
            self.issues.append((self.declared_vars[var], f"Variable '{var}' declared but not used", f"Declaration of {var}", "Low"))

    def report(self):
        if not self.issues:
            print("No vulnerabilities found.")
            return

        # Print detected issues to console
        for issue in self.issues:
            print(f"[!] Line {issue[0]}: {issue[1]}\n    Code: {issue[2]}\n    Severity: {issue[3]}\n")

        output = [
            {
                "line": issue[0],
                "description": issue[1],
                "code": issue[2],
                "severity": issue[3]
            } for issue in self.issues
        ]

        with open("output/report.json", "w") as f:
            json.dump(output, f, indent=4)
            print("[+] Report saved to output/report.json")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <filename.c>")
        sys.exit(1)

    try:
        # Read the file content
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            code_lines = f.readlines()

        analyzer = CSASTAnalyzer(code_lines)
        analyzer.analyze()
        analyzer.report()
    except Exception as e:
        print(f"Error: {e}")
