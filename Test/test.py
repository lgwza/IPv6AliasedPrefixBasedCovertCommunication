from typing import List, Tuple

def generate_tuples(n: int) -> List[Tuple[int, int]]:
    return [(i, i) for i in range(1, n+1)]

# 例子
result = generate_tuples(5.5)
print(result)
