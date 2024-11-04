
'''
    Custom Exception Should Goes Here
'''

class RegisterError(Exception):
    def __init__(self, task_id=-1):
        self.message = f"Failed to register task with id {task_id}."
        super().__init__(self.message)

class ResourceInsufficientError(Exception):
    def __init__(self, task_id=-1):
        self.message = f"Resource insufficient to start task with id {task_id}."
        super().__init__(self.message)

class ParseError(Exception):
    def __init__(self, message="Failed to parse certificate in ASN.1 formar."):
        self.message = message
        super().__init__(self.message)

class RetriveError(Exception):
    def __init__(self, message="Failed to retrieve certificates."):
        self.message = message
        super().__init__(self.message)

class UnknownError(Exception):
    def __init__(self, message="Should not appear") -> None:
        self.message = message
        super().__init__(self.message)

class UnknownTableError(Exception):
    def __init__(self, table_name=""):
        self.message = f"Cannot find table {table_name} in the database."
        super().__init__(self.message)


# Used for building fingerprints
class UnsupportedStringTypeError(Exception):
    def __init__(self, obj_type=None) -> None:
        self.message = f"Unsupported asn.1 struct string type: {obj_type}"
        super().__init__(self.message)

class UnsupportedIntegerTypeError(Exception):
    def __init__(self, obj_type=None) -> None:
        self.message = f"Unsupported asn.1 struct int type: {obj_type}"
        super().__init__(self.message)
