
from dataclasses import dataclass, field

@dataclass
class AnalyzeConfig:
    # Task flag constants (bitwise OR for multiple subtasks)
    TASK_CERT_FP: int = field(init=False, default=0b1)  # for parsing certificates
    TASK_CERT_PARSE: int = field(init=False, default=0b10)  # for cert parse
    TASK_CERT_REVOKE: int = field(init=False, default=0b100) # for checking revocation
    TASK_CAG: int = field(init=False, default=0b1000) # for building CAG for certain webpages

    TASK_CERT_SECURITY: int = field(init=False, default=0b10000) # for checking cert content conform
    TASK_WEB_SECURITY: int = field(init=False, default=0b100000) # for checking web tls deployment

    TASK_CA_PROFILE: int = field(init=False, default=0b1000000)  # for ca
    TASK_CERT_TRUST: int = field(init=False, default=0b10000000)  # for checking cert trust

    # the output_dir if applies
    out_dir: str = r"out"

    # cert_table determines which certificate table to analyze.
    cert_table: str = "cert"

    # task_flag controls which subtasks to run.
    # combine the subtask flags above using bitwise OR.
    task_flag: int = 0b0001

    # single_task_workload sets how many certificates each task should handle.
    single_task_workload: int = 2000

    # max_tasks_parallel limits the maximum number of concurrent tasks.
    max_tasks_parallel: int = 100

    start_id: int = 0

