import re


class Result:
    def __init__(self, rule_name, result, wtype, wmessage) -> None:
        self.rule_name = rule_name
        self.is_compliant = result
        self.type = wtype
        self.message = wmessage
        self.link = f"[\u001b]8;;https://tqrg.github.io/secomlint/#/secomlint-rules?id={self.rule_name.replace('_', '-')}\u001b\\{self.rule_name}\u001b]8;;\u001b\\]"


class Rule:
    def __init__(self, name, active, wtype, value, section) -> None:
        self.name = name
        self.active = active
        self.wtype = wtype
        self.value = value
        self.section = section

    def header_max_length(self, section):
        """rule: header_max_length"""
        section_text = section.text
        if len(section_text) <= self.value:
            return Result('header_max_length', True, self.wtype,
                           f'Header size is within the max length ({self.value} chars).')
        return Result('header_max_length', False, self.wtype,
                       f'Header has more than {self.value} chars.')

    def header_is_not_empty(self, section):
        """rule: header_is_not_empty"""
        section_text = section.text
        if len(section_text) > self.value:
            return Result('header_is_not_empty', True, self.wtype,
                           'Header is not empty.')
        return Result('header_is_not_empty', False, self.wtype,
                       'Header is empty.')

    def header_starts_with_tag(self, section):
        """rule: header_starts_with_tag"""
        section_text = section.text
        if re.search(rf"^{self.value}.*", section_text):
            return Result('header_starts_with_type', True, self.wtype,
                           f'Header starts with {self.value} type')
        return Result('header_starts_with_type', False, self.wtype,
                       f'Header is missing the {self.value} type at the start.')

    def header_has_weakness(self, section):
        """rule: header_has_weakness
           condition: header contains entity:weakness"""
        entities = section.entities

        print(entities)
        if entities:
            weakness = [list(entity)[0]
                        for entity in entities if list(entity)[1] == 'CWEID']
            if weakness:
                return Result('explanation_has_weakness', True, self.wtype,
                            'Explanation mentions a weakness (CWE) id.')
            return Result('explanation_has_weakness', False, self.wtype,
                        'Explanation has tag weakness but a weakness (CWE) id was not mentioned.')
        return Result('explanation_has_weakness', False, self.wtype,
                'Explanation section is missing weakness tag/mention.')




    def header_ends_with_severity(self, section):
        """rule: header_ends_with_severity"""
        def severity_in_the_end(value, text):
            # return re.search(rf".*{value}(\))?$", text)
            return re.search(rf"\(severity: {value}\)$", text)
        section_text = section.lines
        if self.value == 'entity':
            entities = section.entities
            if entities:
                severity = [list(entity)[0]
                           for entity in entities if list(entity)[1] == 'SEVERITY']
                if severity:
                    if severity_in_the_end(severity[0].lower(), section_text):
                        return Result('header_ends_with_severity', True, self.wtype,
                                       'Header ends with SEVERITY.')
        else:
            if severity_in_the_end(self.value.lower(), section_text):
                return Result('header_ends_with_severity', True, self.wtype,
                               'Header ends with SEVERITY')
        return Result('header_ends_with_severity', False, self.wtype,
                       'Header is missing SEVERITY at the end.')


    def summary_has_what(self, section):
        """rule:summary_has_what """
        pass

    def summary_what_identifies_weakness(self, section):
        """rule: summary_what_identifies_weakness"""
        pass

    def summary_has_why(self, section):
        """rule: summary_has_why"""
        pass

    def summary_has_how(self, section):
        """rule: summary_has_how"""
        pass

    def summary_has_when(self,section):
        """rule: summary_has_when"""
        pass

    def summary_max_length(self, section):
        """rule: summary_max_length"""
        section_text = section.lines
        if section.lines and len(section_text) <= self.value:
            return Result('summary_max_length', True, self.wtype,
                           f'Summary size is within the max length ({self.value} chars).')
        return Result('summary_max_length', False, self.wtype,
                       f'Summary has more than {self.value} chars.')


    def explanation_is_not_empty(self, section):
        """rule: explanation_is_not_empty"""
        section_text = section.lines
        if len(section_text) > self.value:
            return Result('explanation_is_not_empty', True, self.wtype,
                           'Explanation is not empty.')
        return Result('explanation_is_not_empty', False, self.wtype,
                       'Explanation is empty.')

    def explanation_has_weakness(self, section):
        if 'weakness' == section.tag:
            entities = section.entities
            if entities:
                weakness = [list(entity)[0]
                            for entity in entities if list(entity)[1] == 'CWEID']
                if weakness:
                    return Result('explanation_has_weakness', True, self.wtype,
                                   'Explanation mentions a weakness (CWE) id.')
                return Result('explanation_has_weakness', False, self.wtype,
                               'Explanation has tag weakness but a weakness (CWE) id was not mentioned.')
        return Result('explanation_has_weakness', False, self.wtype,
                       'Explanation section is missing weakness tag/mention.')

    def explanation_has_severity(self, section):
        if 'severity' == section.tag:
            entities = section.entities
            if entities:
                severity = [list(entity)[0] for entity in entities if list(
                    entity)[1] == 'SEVERITY']
                if severity:
                    return Result('explanation_has_severity', True, self.wtype,
                                   f'Explanation mentions severity.')
                return Result('explanation_has_severity', False, self.wtype,
                               f'Explanation section has severity tag but is missing vulnerability severity /mention.')
        return Result('explanation_has_severity', False, self.wtype,
                       f'Explanation section is missing vulnerability severity tag/mention.')

    def explanation_has_location_file(self, section):
        """rule:explanation_has_location_file"""
        pass


    def explanation_has_location_method(self, section):
        """rule:explanation_has_location_methodx"""
        pass
    

    def explanation_has_location_line(self, section):
        """rule:explanation_has_location_line"""
        pass


    def explanation_has_unchecked_vars(self, section):
        """rule:explanation_has_unchecked_vars"""
        pass


    def explanation_has_checked_vars(self, section):
        """rule:explanation_has_checked_vars"""
        pass
    
    def explanation_has_sources(self, section):
        """rule:explanation_has_sources"""
        pass


    def explanation_has_sinks(self, section):
        """rule:explanation_has_sinks"""
        pass


    def metadata_has_report(self, section):
        if 'report' == section.tag:
            entities = section.entities
            if entities:
                url = [list(entity)[0]
                       for entity in entities if list(entity)[1] == 'URL']
                if url:
                    return Result('metadata_has_report', True, self.wtype,
                                   f'Metadata mentions report.')
            return Result('metadata_has_report', False, self.wtype,
                           f'Metadata has report tag but does not have link to it.')
        return Result('metadata_has_report', False, self.wtype,
                       f'Metadata section is missing report tag/mention.')

    def metadata_has_cvss(self, section):
        if 'cvss' == section.tag and section.lines:
            return Result('metadata_has_cvss', True, self.wtype,
                           f'Metadata mentions cvss score.')
        return Result('metadata_has_cvss', False, self.wtype,
                       f'Metadata section is missing cvss tag/mention.')

    def metadata_has_introduced_in(self, section):
        if 'introduced_in' == section.tag:
            entities = section.entities
            if entities:
                sha = [list(entity)[0]
                       for entity in entities if list(entity)[1] == 'SHA']
                if sha:
                    return Result('metadata_has_introduced_in', True, self.wtype,
                                   f'Metadata mentions sha where vulnerability was introduced in.')
            return Result('metadata_has_introduced_in', False, self.wtype,
                           f'Metadata mentions introduced in tag but no sha was found.')
        return Result('metadata_has_introduced_in', False, self.wtype,
                       f'Metadata section is missing introduced in tag/mention.')

    def reporter_has_reported_by(self, section):
        """rule:reporter_has_reported_by"""
        if 'reported_by' == section.tag and section.lines:
            entities = section.entities
            email = [list(entity)[0]
                     for entity in entities if list(entity)[1] == 'EMAIL']
            if email:
                return Result('reporter_has_reported_by', True, self.wtype,
                               f'Contacts section includes {self.value} info.')
            return Result('reporter_has_reported_by', False, 0,
                           f'Contacts section includes tag for {self.value} but email is missing.')
        return Result('reporter_has_reported_by', False, self.wtype,
                       f'Contacts section is missing {self.value} info.')

    def reporter_has_co_authored_by(self, section):
        if 'co_authored_by' == section.tag and section.lines:
            entities = section.entities
            email = [list(entity)[0]
                     for entity in entities if list(entity)[1] == 'EMAIL']
            if email:
                return Result('reporter_has_co_authored_by', True, self.wtype,
                               f'Contacts section includes {self.value} info.')
            return Result('reporter_has_co_authored_by', True, 0,
                           f'Contacts section includes tag or mention for {self.value} but email is missing.')
        return Result('reporter_has_co_authored_by', False, self.wtype,
                       f'Contacts section is missing {self.value} info.')

    def reporter_identifies_detection_strategy(self, section):
        if 'reference' == section.tag and section.lines:
            line = ''.join(section.lines)
            if 'bug-tracker' in line:
                entities = section.entities
                url = [list(entity)[0]
                       for entity in entities if list(entity)[1] == 'URL']
                if url:
                    return Result('reporter_identifies_detection_strategy', True, self.wtype,
                                   f'Reporter includes tooling.')
                return Result('reporter_identifies_detection_strategy', False, self.wtype,
                               f'Reporter Bug tracker section mentions bug tracker but is missing url to it.')

            if 'resolves' in line or 'see also' in line:
                entities = section.entities
                issue = [list(entity)[0]
                         for entity in entities if list(entity)[1] == 'ISSUE']
                if issue:
                    return Result('bugtracker_has_reference', True, self.wtype,
                                   f'Bug tracker section includes references to issues.')

        return Result('bugtracker_has_reference', False, self.wtype,
                       f'Bug tracker section is missing bug-tracker info.')
