using System;
using System.Collections.Generic;
using System.Text;

namespace Security.AccessTokenHandling.OAuthServer {

  public interface IAuthPageBuilder {

    string GetCustomPage(string customHtmlBodyTemplate);

    /// <summary>
    /// Generates the HTML LOGON Form
    /// </summary>
    /// <param name="responseType"></param>
    /// <param name="prompt"></param>
    /// <param name="login_hint"></param>
    /// <param name="state"></param>
    /// <param name="clientId"></param>
    /// <param name="redirectUri"></param>
    /// <param name="requestedScopes"></param>
    /// <param name="viewMode">1=regular page / 2=optimized page for embedding in iframes (small width + white bg)</param>
    /// <param name="error"></param>
    /// <returns></returns>
    string GetAuthForm(
      string responseType,
      string prompt,
      string login_hint,
      string state,
      string clientId,
      string redirectUri,
      string requestedScopes,
      int viewMode,
      string error
    );

    /// <summary>
    /// Generates the HTML LOGON Form
    /// </summary>
    /// <param name="responseType"></param>
    /// <param name="prompt"></param>
    /// <param name="identifiedWinUser"></param>
    /// <param name="state"></param>
    /// <param name="clientId"></param>
    /// <param name="redirectUri"></param>
    /// <param name="requestedScopes"></param>
    /// <param name="viewMode">1=regular page / 2=optimized page for embedding in iframes (small width + white bg)</param>
    /// <param name="error"></param>
    /// <returns></returns>
    string GetWinAuthForm(
      string responseType,
      string prompt,
      string identifiedWinUser,
      string state,
      string clientId,
      string redirectUri,
      string requestedScopes,
      int viewMode,
      string error
    );

    /// <summary>
    /// Generates the HTML SCOPE SELECTION Form (Step 2)
    /// </summary>
    /// <param name="responseType"></param>
    /// <param name="prompt"></param>
    /// <param name="otp"></param>
    /// <param name="state"></param>
    /// <param name="clientId"></param>
    /// <param name="redirectUri"></param>
    /// <param name="requestedScopes"></param>
    /// <param name="availableScopes"></param>
    /// <param name="viewMode">1=regular page / 2=optimized page for embedding in iframes (small width + white bg)</param>
    /// <param name="error"></param>
    /// <returns></returns>
    string GetScopeConfirmationForm(
      string responseType,
      string prompt,
      string otp,
      string state,
      string clientId,
      string redirectUri,
      string requestedScopes,
      ScopeDescriptor[] availableScopes,
      int viewMode,
      string error
    );

    /// <summary>
    /// Generates a HTML ERROR PAGE
    /// </summary>
    /// <param name="message"></param>
    /// <param name="viewMode">1=regular page / 2=optimized page for embedding in iframes (small width + white bg)</param>
    /// <returns></returns>
    string GetErrorPage(string message, int viewMode);

  }

}
