Keyboard caching is caused by the `UITextInputTraits` protocol supported by `UITextField`, `UITextView` and `UISearchBar`.

To prevent keyboard caching from leaking input of sensitive fields, consider:

- `autocorrectionType` determines whether auto-correction is enabled during typing. The default value of this property is `UITextAutocorrectionTypeDefault`, which for most input methods enables auto-correction.

```swift
let textField = UITextField(frame: CGRect(x: 0, y: 0, width: 200, height: 40))
textField.autocorrectionType = .no // Disable autocorrection
```

- `isSecureTextEntry` determines whether text copying and caching are disabled and hides the text being
  entered for `UITextField`. The default value of this property is `NO`.

```swift
let textField = UITextField(frame: CGRect(x: 0, y: 0, width: 200, height: 40))
textField.isSecureTextEntry = true // Enable secure text entry
```