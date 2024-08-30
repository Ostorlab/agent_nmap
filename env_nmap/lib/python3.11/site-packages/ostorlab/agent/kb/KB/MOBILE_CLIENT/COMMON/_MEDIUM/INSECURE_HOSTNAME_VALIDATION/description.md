The application performs insecure hostname validation using easy to bypass methods like `startsWith` or `endsWith`. An
attacker can easily bypass this check by registering a domain that matches the check pattern.

Composite checks with both `startsWith` and `endsWith` are equally insecure as the attack can still create domain with
random middle input that matches the checked pattern.
