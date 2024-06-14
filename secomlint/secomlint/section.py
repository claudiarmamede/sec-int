import re
from tags import HEADER, SUMMARY, EXPLANATION, REPORTER
from operator import itemgetter
"""This module abstracts the different sections of a report."""


class Section:
    def __init__(self, text : str = None, entities : list = None) -> None:
        self.text = text
        self.entities = entities if entities is not None else []
        self.lines = text.splitlines() if text is not None else []
        self.tags = {}
        if len(self.lines) > 0 : self.set_tags()


    def set_entities(self, entities : list):
        self.entities = entities

    def get_tags(self):
        return self.tags.values()

    def get_entities(self):
        return self.entities
    
    def set_tags(self):
        pass 
    
    
class Header(Section):
    def __init__(self, text=None, entities=None) -> None:
        super().__init__(text, entities)
    
    def set_tags(self):
        def match_header_tags(line):
            return re.findall(rf"^({'|'.join(HEADER)})", line, re.IGNORECASE | re.MULTILINE )
        
        for line in self.lines:
            self.tags[line] = match_header_tags(line) # each line can only have 1 tag
    
class Summary(Section):
    def __init__(self, text=None, entities=None) -> None:
        super().__init__(text, entities)

    def set_tags(self):
        def match_summary_tags(lines): 
            return re.findall(rf"^({'|'.join(SUMMARY)})", lines, re.IGNORECASE | re.MULTILINE )
        
        for line in self.lines:
            self.tags[line] = match_summary_tags(line)



class Explanation(Section):
    def __init__(self, text=None, entities=None) -> None:
        super().__init__(text, entities)

        
    def set_tags(self):
        def match_explanation_tags(lines): 
            return re.findall(rf"^({'|'.join(EXPLANATION)})", lines, re.IGNORECASE | re.MULTILINE )
        
        for line in self.lines:
            self.tags[line] = match_explanation_tags(line)


class Reporter(Section):
    def __init__(self, text=None, entities=None) -> None:
        super().__init__(text, entities)


    def set_tags(self):
        def match_reporter_tags(lines):
            return re.findall(rf"^({'|'.join(REPORTER)})", lines, re.IGNORECASE | re.MULTILINE )

        for line in self.lines:
            self.tags[line] = match_reporter_tags(line)
