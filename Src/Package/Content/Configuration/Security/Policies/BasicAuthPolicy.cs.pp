namespace $rootnamespace$.Configuration.Security.Policies
{
  using System;
  using System.Collections.Generic;
  using System.Configuration;
  using System.Text;
  using System.Web;
  using FluentSecurity;
  using FluentSecurity.Policy;
  using Handlers;

  public class BasicAuthPolicy : ISecurityPolicy
  {
    private IDictionary< string, string > activeUsers = new Dictionary< string, string >
    {
      {
        ConfigurationManager.AppSettings[ "BasicAuth.Username" ],
        ConfigurationManager.AppSettings[ "BasicAuth.Password" ]
      }
    };

    protected virtual bool ExtractBasicCredentials( string authorizationHeader, ref string username, ref string password )
    {
      if( string.IsNullOrEmpty( authorizationHeader ) )
        return false;

      var verifiedAuthorizationHeader = authorizationHeader.Trim();
      if(
        verifiedAuthorizationHeader.IndexOf( BasicAuthConstants.HttpBasicSchemeName,
          StringComparison.InvariantCultureIgnoreCase ) != 0 )
      {
        return false;
      }

      verifiedAuthorizationHeader =
        verifiedAuthorizationHeader.Substring( BasicAuthConstants.HttpBasicSchemeName.Length,
          verifiedAuthorizationHeader.Length - BasicAuthConstants.HttpBasicSchemeName.Length ).Trim();

      var credentialBase64DecodedArray = Convert.FromBase64String( verifiedAuthorizationHeader );
      var decodedAuthorizationHeader = Encoding.UTF8.GetString( credentialBase64DecodedArray, 0,
        credentialBase64DecodedArray.Length );

      var separatorPosition = decodedAuthorizationHeader.IndexOf( BasicAuthConstants.HttpCredentialSeparator );

      if( separatorPosition <= 0 )
        return false;

      username = decodedAuthorizationHeader.Substring( 0, separatorPosition ).Trim();
      password =
        decodedAuthorizationHeader.Substring( separatorPosition + 1,
          ( decodedAuthorizationHeader.Length - separatorPosition - 1 ) ).Trim();

      return !string.IsNullOrEmpty( username ) && !string.IsNullOrEmpty( password );
    }

    public PolicyResult Enforce( ISecurityContext securityContext )
    {
      var context = HttpContext.Current;
      var authorizationHeader = context.Request.Headers[ BasicAuthConstants.HttpAuthorizationHeader ];

      string userName = null;
      string password = null;
      if( !ExtractBasicCredentials( authorizationHeader, ref userName, ref password ) )
        return PolicyResult.CreateFailureResult( this, "Access denied!" );

      if( !ValidateCredentials( userName, password ) )
        return PolicyResult.CreateFailureResult( this, "Access denied!" );

      var authCookie = context.Request.Cookies.Get( BasicAuthConstants.AuthenticationCookieName );
      if( authCookie != null ) return PolicyResult.CreateSuccessResult( this );

      authCookie = new HttpCookie( BasicAuthConstants.AuthenticationCookieName, "1" )
      {
        Expires = DateTime.Now.AddHours( 1 )
      };
      context.Response.Cookies.Add( authCookie );

      return PolicyResult.CreateSuccessResult( this );
    }

    protected virtual bool ValidateCredentials( string userName, string password )
    {
      return activeUsers.ContainsKey( userName ) && activeUsers[ userName ] == password;
    }
  }
}