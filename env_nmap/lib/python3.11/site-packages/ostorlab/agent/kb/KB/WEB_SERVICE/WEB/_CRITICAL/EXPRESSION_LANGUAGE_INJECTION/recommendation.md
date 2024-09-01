To secure the application against Expression Language Injection (EL Injection), consider the following recommendations:

- __Avoid Direct User Input Use__: Whenever possible, avoid directly using user inputs in EL expressions. Instead, prefer a whitelist approach where only predefined, safe values are allowed to be used in EL expressions.

- __Input Validation__: Validate and sanitize user inputs before using them in EL expressions. Implement strict validation to accept only expected data types and patterns.

- __Context-Specific Encoding__: Use encoding functions provided by your framework or libraries (e.g., \<c:out> in JSP, fn:escapeXml() in JSTL) to ensure context-aware output encoding. This prevents the interpretation of user inputs as code.

### Example

=== "Java"
  ```java
    @RestController
    public class MathExpressionController {
    
        private final ExpressionParser parser = new SpelExpressionParser();
    
        @GetMapping("/evaluate")
        public String evaluateExpression(@RequestParam String expression) {
            String sanitizedExpression = sanitizeInput(expression);
            Expression exp = parser.parseExpression(sanitizedExpression);
            try {
                Object result = exp.getValue();
                return "Result: " + result.toString();
            } catch (Exception e) {
                return "Error: Invalid expression";
            }
        }
    
        private String sanitizeInput(String input) {
            // Implement your input sanitization logic here
            // For this example, allow only basic arithmetic operations and numbers
            input = input.replaceAll("[^0-9\\+\\-\\*/]", ""); // Allow only digits, +, -, *, /
            return input;
        }
    }
  ```