
def ascii_print(func):

    def print_wrapper(content, indent=0):
        try:
            func(content, indent=0)
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            danger(e)

    return print_wrapper


@ascii_print
def warn(content, indent=0):
    indents = ''
    for i in range(0, indent):
        indents += '    '
    print(indents + '\033[93m'+str(content)+'\033[0m')


@ascii_print
def ok(content, indent=0):
    indents = ''
    for i in range(0, indent):
        indents += '    '
    print(indents + '\033[92m'+str(content)+'\033[0m')


@ascii_print
def info(content, indent=0):
    indents = ''
    for i in range(0, indent):
        indents += '    '
    print(indents + '\033[94m'+str(content)+'\033[0m')


@ascii_print
def danger(content, indent=0):
    indents = ''
    for i in range(0, indent):
        indents += '    '
    print(indents + '\033[91m'+str(content)+'\033[0m')


@ascii_print
def log(content, indent=0):
    indents = ''
    for i in range(0, indent):
        indents += '    '
    print(indents + str(content))
