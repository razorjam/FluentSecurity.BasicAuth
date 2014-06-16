namespace $rootnamespace$.Configuration.Security.Handlers
{
  using System.Web;
  using System.Web.Mvc;
  using FluentSecurity;

  public class BasicAuthPolicyViolationHandler : IPolicyViolationHandler
  {
    public ActionResult Handle( PolicyViolationException exception )
    {
      var context = HttpContext.Current;

      var authCookie = context.Request.Cookies.Get( BasicAuthConstants.AuthenticationCookieName );
      if( authCookie != null )
        throw new HttpException( BasicAuthConstants.HttpNotAuthorizedStatusCode, "Auth required" );
      context.Response.Clear();
      context.Response.StatusCode = BasicAuthConstants.HttpNotAuthorizedStatusCode;
      context.Response.AddHeader( BasicAuthConstants.HttpWwwAuthenticateHeader,
        string.Format( "Basic realm =\"{0}\"", BasicAuthConstants.Realm ) );
      context.Response.End();

      throw new HttpException( BasicAuthConstants.HttpNotAuthorizedStatusCode, "Auth required" );
    }
  }

  public static class BasicAuthConstants
  {
    public const string AuthenticationCookieName = "BasicAuthentication";
    public const string HttpWwwAuthenticateHeader = "WWW-Authenticate";
    public const string HttpAuthorizationHeader = "Authorization";
    public const string HttpBasicSchemeName = "Basic";
    public const char HttpCredentialSeparator = ':';
    public const int HttpNotAuthorizedStatusCode = 401;
    public const string Realm = "demo";
  }
}