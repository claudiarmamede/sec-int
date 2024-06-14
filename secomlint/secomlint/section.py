"""This module abstracts the different sections of a report."""

class Section:
    def __init__(self) -> None:
        self.lines:str
        self.entities = []
        self.tag = None

    def set_lines(self, lines):
        self.lines = lines

    def set_entities(self, entities):
        self.entities = entities

    def set_tag(self, tag):
        self.tag = tag


class Header(Section):
    def __init__(self, lines=None, entities=None) -> None:
        super().__init__()
        super().set_lines(lines)
        super().set_entities(entities)


class Summary(Section):
    def __init__(self, lines=None, tag=None, entities=None) -> None:
        super().__init__()
        super().set_lines(lines)
        super().set_entities(entities)
        super().set_tag(tag)


class Explanation(Section):
    def __init__(self, lines=None, tag=None, entities=None) -> None:
        super().__init__()
        super().set_lines(lines)
        super().set_entities(entities)
        super().set_tag(tag)


class Reporter(Section):
    def __init__(self, lines=None, tag=None, entities=None) -> None:
        super().__init__()
        super().set_lines(lines)
        super().set_entities(entities)
        super().set_tag(tag)