
from reqsum.parser import parse_line

def test_parse_requirement():
    ln = parse_line("requests>=2.0; python_version>='3.8'\n")
    assert ln.kind == 'requirement'
    assert ln.name == 'requests'
    assert str(ln.req.specifier) == ">=2.0"

def test_parse_include():
    ln = parse_line("-r base.txt\n")
    assert ln.kind == 'include'

def test_parse_blank_comment():
    assert parse_line("\n").kind == 'blank'
    assert parse_line("# hi\n").kind == 'comment'
