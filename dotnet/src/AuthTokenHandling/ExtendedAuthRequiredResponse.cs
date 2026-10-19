using System;
using System.Reflection;

namespace Security.AccessTokenHandling {

  /// <summary>
  /// Describes additional HTTP response data for an authentication-required validation outcome without depending on a specific web framework.
  /// </summary>
  public sealed class ExtendedAuthRequiredResponse {

    private int _StatusCode;
    private string _ReasonPhrase;
    private HttpResponseHeader[] _Headers;

    public ExtendedAuthRequiredResponse() {
      _StatusCode = 0;
      _ReasonPhrase = null;
      _Headers = new HttpResponseHeader[] { };
    }

    /// <summary>
    /// Gets or sets the HTTP status code to write. A value less than 100 means that the caller should keep its existing status code.
    /// </summary>
    public int StatusCode {
      get {
        return _StatusCode;
      }
      set {
        _StatusCode = value;
      }
    }

    /// <summary>
    /// Gets or sets the optional low-detail reason phrase or response body text.
    /// </summary>
    public string ReasonPhrase {
      get {
        return _ReasonPhrase;
      }
      set {
        _ReasonPhrase = value;
      }
    }

    /// <summary>
    /// Gets or sets the HTTP headers that should be emitted by the HTTP adapter.
    /// </summary>
    public HttpResponseHeader[] Headers {
      get {
        return _Headers;
      }
      set {
        if (value == null) {
          _Headers = new HttpResponseHeader[] { };
        }
        else {
          _Headers = value;
        }
      }
    }

  }

  /// <summary>
  /// Represents a response header that can be emitted by an HTTP adapter.
  /// </summary>
  public sealed class HttpResponseHeader {

    private string _Name;
    private string _Value;

    public HttpResponseHeader() {
    }

    public HttpResponseHeader(string name, string value) {
      _Name = name;
      _Value = value;
    }

    /// <summary>
    /// Gets or sets the header name.
    /// </summary>
    public string Name {
      get {
        return _Name;
      }
      set {
        _Name = value;
      }
    }

    /// <summary>
    /// Gets or sets the header value.
    /// </summary>
    public string Value {
      get {
        return _Value;
      }
      set {
        _Value = value;
      }
    }

  }

  /// <summary>
  /// Provides context for creating an extended authentication-required response.
  /// </summary>
  public sealed class ExtendedAuthRequiredResponseContext {

    private AccessTokenValidator.ValidationOutcome _ValidationOutcome;
    private int _StatusCode;
    private string _ReasonPhrase;
    private Type _ContractType;
    private MethodInfo _TargetContractMethod;
    private string _CallingMachine;
    private string[] _RequiredApiPermissions;

    public ExtendedAuthRequiredResponseContext(
      AccessTokenValidator.ValidationOutcome validationOutcome,
      int statusCode,
      string reasonPhrase,
      Type contractType,
      MethodInfo targetContractMethod,
      string callingMachine,
      string[] requiredApiPermissions
    ) {
      _ValidationOutcome = validationOutcome;
      _StatusCode = statusCode;
      _ReasonPhrase = reasonPhrase;
      _ContractType = contractType;
      _TargetContractMethod = targetContractMethod;
      _CallingMachine = callingMachine;
      if (requiredApiPermissions == null) {
        _RequiredApiPermissions = new string[] { };
      }
      else {
        _RequiredApiPermissions = requiredApiPermissions;
      }
    }

    /// <summary>
    /// Gets the validation outcome that caused the HTTP rejection.
    /// </summary>
    public AccessTokenValidator.ValidationOutcome ValidationOutcome {
      get {
        return _ValidationOutcome;
      }
    }

    /// <summary>
    /// Gets the already selected HTTP status code.
    /// </summary>
    public int StatusCode {
      get {
        return _StatusCode;
      }
    }

    /// <summary>
    /// Gets the already selected low-detail reason phrase.
    /// </summary>
    public string ReasonPhrase {
      get {
        return _ReasonPhrase;
      }
    }

    /// <summary>
    /// Gets the contract type being called, if available.
    /// </summary>
    public Type ContractType {
      get {
        return _ContractType;
      }
    }

    /// <summary>
    /// Gets the target contract method being called, if available.
    /// </summary>
    public MethodInfo TargetContractMethod {
      get {
        return _TargetContractMethod;
      }
    }

    /// <summary>
    /// Gets the calling machine identifier supplied to the validator.
    /// </summary>
    public string CallingMachine {
      get {
        return _CallingMachine;
      }
    }

    /// <summary>
    /// Gets the explicitly required API permissions for the call.
    /// </summary>
    public string[] RequiredApiPermissions {
      get {
        return _RequiredApiPermissions;
      }
    }

  }

}
