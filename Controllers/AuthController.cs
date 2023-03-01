using ASOnlineSAMLWebApp.App_Start;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Mvc;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Security.Claims;
using System.Web.Mvc;
using ASOnlineSAMLWebApp.Identity;

namespace ASOnlineSAMLWebApp.Controllers
{
    [AllowAnonymous]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;
        public AuthController()
        {
            config = IdentityConfig.Saml2Configuration;
        }
        public ActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config){ }).ToActionResult();
        }
        public ActionResult AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            saml2AuthnResponse.CreateSession(claimsAuthenticationManager: new DefaultClaimsAuthenticationManager());

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }
        [ValidateAntiForgeryToken]
        public ActionResult Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var logoutRequest = new Saml2LogoutRequest(config, ClaimsPrincipal.Current).DeleteSession();
            return binding.Bind(logoutRequest).ToActionResult();
        }
    }
}