To limit one's exposure to this type of attack, consider the following recommendations: 

- Avoid exporting components unless the component is specifically designed to handle requests from untrusted applications. 
- Be aware that declaring an intent filter will automatically export the component, exposing it to public access.
- Avoid placing critical, state-changing actions in exported components. 
- If a single component handles both inter-application and intra-application requests, the developer should consider dividing that component into separate components.
- If a component must be exported (e.g., to receive system broadcasts), then the component should dynamically check the caller's identity prior to performing any operations. 
- Require Signature or SignatureOrSystem permissions to limit component's exposure to a set of trusted applications. 
- Check the caller's identity prior to returning return values of exported components as they can leak private data.
