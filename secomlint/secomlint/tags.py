from secomlint.utils import extend_tags
# Assumes tags appear in the begginging of the text. Alter this in section.py
HEADER = ['vuln-detect']

SUMMARY = ['what', 'why', 'how', 'when', 'where']

EXPLANATION = ['unchecked-vars', 'check-vars', 'taint', 'sources', 'sinks', 'extra', 'additional']

REPORTER = ['reported-by', 'co-authored-by', 'method', 'tool', 'strategy', 'reference', 'url']
