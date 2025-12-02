def final_sink(data):
    eval(data)
def level_2_caller(data):
    final_sink(data)
def level_1_caller(data):
    level_2_caller(data)
def entry_point():
    level_1_caller('test')
def safe_func():
    return 1
