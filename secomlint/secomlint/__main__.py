import sys
import click
import os

from report import Report
from compliance import Compliance
from ruler import Ruler
from config import Config
# from informativeness import Informativeness
# from generation import Generation

from tqdm import tqdm


def read_report(fpath:str) -> str: 
    """Read and parse report"""
    try:
        with open(fpath, 'r') as f:
            raw_report = f.read()
            report = Report(raw_report)
            report.parse()
            return report
    except Exception as exc:
        print (f"An error occurred: {exc}")
        return None


@click.command()
@click.option("--report", default="reports/report.txt", help="Report file path")
@click.option("--compliance", is_flag=True, default=True, help="Show compliance report.") # TODO: change to False
@click.option("--score", is_flag=True, default=False, help="Show compliance score.")
@click.option("--quiet", is_flag=True, default=False, help="Show only compliance errors and warnings.")
@click.option("--informativeness", is_flag=True, default=False, help="Checks how informative is the body.")
@click.option("--out", help="Output report to file name.")
@click.option("--rules-config", default="config/rules.yml", help="Rule configuration file path name.")
def main(report:str, compliance:bool, score:bool, quiet:bool, informativeness:bool, out:str, rules_config:str):
    report = read_report(report)
    if not report: 
        print(f"❌ Can't read report at {report}") 
        return
   
    if compliance:
        compliance = Compliance(path_config=rules_config)
        compliance.check(report)
        compliance.calculate_score()
        compliance.report(quiet, score, out)
        
    if informativeness:
        report
        pass
        # if not sys.stdin.isatty(): 
        #     message = read_message()
        #     if message.sections:
        #         informativeness = Informativeness(message)
        #         informativeness.check_body()
        #         informativeness.report(True, False)

    return


if __name__ == '__main__':
    main()
