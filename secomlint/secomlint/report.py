import re

from section import Header, Summary, Explanation, Reporter
from extractor import Extractor
from tags import HEADER, SUMMARY, EXPLANATION, REPORTER


class Report:
    def __init__(self, lines) -> None:
        self.raw_text = lines
        self.text = lines
        self.sections = []


    def parse(self):
        def is_header(lines):
            return re.search(rf"({'|'.join(HEADER)}):", lines, re.IGNORECASE)

        def is_summary(lines): 
            return re.search(rf"({'|'.join(SUMMARY)}):", lines, re.IGNORECASE)

        def is_explanation(lines): 
            return re.search(rf"({'|'.join(EXPLANATION)}):", lines, re.IGNORECASE)

        def is_reporter(lines):
            return re.search(rf"({'|'.join(REPORTER)}):", lines, re.IGNORECASE)

        # Split into sections based on new lines
        blocks = re.split(r'\n{2,}', self.text.strip())
        
        # Setup NER extractor
        extractor = Extractor()

        # Parse report into sections and assign a type to each section
        for block in blocks:
                if is_header(block):
                    self.sections.append(
                        Header(lines = block, entities=extractor.entities(block))
                    )
                elif is_summary(block):
                    self.sections.append(
                        Summary(lines = block, entities=extractor.entities(block))
                    )
                elif is_explanation(block):
                    self.sections.append(
                        Explanation(lines = block, entities=extractor.entities(block))
                    )
                elif is_reporter(block):
                    self.sections.append(
                        Reporter(lines = block, entities=extractor.entities(block))
                    )
                else:
                    print(f"Idk what this is {block}")

    def get_sections(self):
        return self.sections

    def get_text(self):
        return self.text
