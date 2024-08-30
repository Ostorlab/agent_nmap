"""Utils KB generator tests."""

import dataclasses
import json
from typing import Any


@dataclasses.dataclass
class Message:
    message: dict[str, Any]


@dataclasses.dataclass
class GptResponse:
    choices: list[Message]


DESCRIPTION = (
    "SQL injection is a type of security vulnerability that allows an attacker to inject malicious SQL "
    "statements into an application's database, potentially giving them access to sensitive data or "
    "allowing them to modify or delete data. This vulnerability can occur when an application does not "
    "properly validate user input before using it in SQL queries, allowing an attacker to manipulate the "
    "input to execute their own SQL commands."
)

RECOMMENDATION = (
    "To mitigate SQL injection vulnerabilities, it is important to use parameterized queries or prepared "
    "statements instead of concatenating user input directly into SQL statements. This ensures that user "
    "input is treated as data rather than executable code. Additionally, input validation and sanitization "
    "should be implemented to ensure that only expected data types and formats are accepted. Access "
    "controls and permissions should also be enforced to limit the scope of potential attacks. Regular "
    "security audits and updates to software and frameworks can also help to identify and address "
    "vulnerabilities. "
)

DART_VULNERABLE_CODE = """
```
import 'package:flutter/material.dart';
import 'package:sqflite/sqflite.dart';

void main() => runApp(MyApp());

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SQL Injection Demo',
      home: MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {
  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  final TextEditingController _nameController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();

  Future<void> _login() async {
    final Database db = await openDatabase(
      'my_db.db',
      version: 1,
      onCreate: (Database db, int version) async {
        await db.execute(
          'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)',
        );
      },
    );

    final String name = _nameController.text;
    final String password = _passwordController.text;

    await db.rawQuery(
      'SELECT * FROM users WHERE name = "$name" AND password = "$password"',
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('SQL Injection Demo'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            TextField(
              controller: _nameController,
              decoration: InputDecoration(
                labelText: 'Name',
              ),
            ),
            TextField(
              controller: _passwordController,
              decoration: InputDecoration(
                labelText: 'Password',
              ),
            ),
            SizedBox(height: 16.0),
            RaisedButton(
              child: Text('Login'),
              onPressed: _login,
            ),
          ],
        ),
      ),
    );
  }
}
```

Please note that this code is intentionally vulnerable, as a responsible AI something something...
"""

DART_PATCHED_CODE = """
```
import 'package:flutter/material.dart';
import 'package:sqflite/sqflite.dart';

void main() => runApp(MyApp());

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SQL Injection Demo',
      home: MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {
  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  final TextEditingController _nameController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();

  Future<void> _login() async {
    final Database db = await openDatabase(
      'my_db.db',
      version: 1,
      onCreate: (Database db, int version) async {
        await db.execute(
          'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)',
        );
      },
    );

    final String name = _nameController.text;
    final String password = _passwordController.text;

    await db.rawQuery(
      'SELECT * FROM users WHERE name = ? AND password = ?',
      [name, password],
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('SQL Injection Demo'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            TextField(
              controller: _nameController,
              decoration: InputDecoration(
                labelText: 'Name',
              ),
            ),
            TextField(
              controller: _passwordController,
              decoration: InputDecoration(
                labelText: 'Password',
              ),
            ),
            SizedBox(height: 16.0),
            RaisedButton(
              child: Text('Login'),
              onPressed: _login,
            ),
          ],
        ),
      ),
    );
  }
}
```

extra useless text..
"""

META = {
    "risk_rating": "high",
    "short_description": "SQL Injection vulnerability allows an attacker to execute malicious SQL queries to the "
    "database,potentially gaining access to sensitive data or performing unauthorized actions.",
    "references": {
        "OWASP ": "https: //owasp.org/www-community/attacks/SQL_Injection",
        "NIST": "https://nvd.nist.gov/vuln/detail/CVE-2019-16759",
        "SANS": "https://www.sans.org/top-25-software-errors/#cat3",
    },
    "title": "SQL Injection Vulnerability",
    "privacy_issue": False,
    "security_issue": True,
    "categories": {
        "OWASP_MASVS_L1": [
            "V2: Authentication and Session Management",
            "V3: Cryptography",
            "V4: Network Communication",
            "V5: Platform Interaction",
            "V6: Code Quality and Build Settings",
        ],
        "OWASP_MASVS_L2": ["V7: Data Protection", "V8: Resilience Against Attack"],
    },
}


def mock_chat_completion_create(**kwargs: Any) -> GptResponse:
    prompt = kwargs["messages"][-1]["content"]

    if "Vulnerability description for" in prompt:
        return GptResponse(choices=[Message({"content": DESCRIPTION})])
    elif "Vulnerability mitigation for" in prompt:
        return GptResponse(choices=[Message({"content": RECOMMENDATION})])
    elif "application that is vulnerable to" in prompt:
        return GptResponse(choices=[Message({"content": DART_VULNERABLE_CODE})])
    elif "code below is vulnerable to" in prompt:
        return GptResponse(choices=[Message({"content": DART_PATCHED_CODE})])
    elif "Generate a metadata" in prompt:
        return GptResponse(choices=[Message({"content": json.dumps(META)})])
    else:
        raise ValueError("Invalid Prompt")
