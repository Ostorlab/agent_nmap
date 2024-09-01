Expression Language Injection (EL Injection) is a critical vulnerability arising from the mishandling of user inputs within expression languages commonly utilized in web applications. These languages serve to dynamically access and modify data. Attackers exploit EL Injection by injecting malicious code into these expressions. This unauthorized tampering can result in severe consequences, including unauthorized access, data breaches, or even the execution of remote code.

EL Injection primarily manifests within frameworks or templates supporting expression languages like JSP (JavaServer Pages), JSF (JavaServer Faces), Apache Struts, Thymeleaf, and various others commonly employed in web application development.

### Example


=== "Java"
  ```java
    @RestController
    public class MathExpressionController {
    
        private final ExpressionParser parser = new SpelExpressionParser();
    
        @GetMapping("/evaluate")
        public String evaluateExpression(@RequestParam String expression) {
            Expression exp = parser.parseExpression(expression);
            try {
                Object result = exp.getValue();
                return "Result: " + result.toString();
            } catch (Exception e) {
                return "Error: Invalid expression";
            }
        }
    
    }
  ```

