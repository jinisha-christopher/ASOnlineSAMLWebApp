using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
//using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Helpers;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Util;
using System.IdentityModel.Claims;
using System.ServiceModel.Security;


namespace ASOnlineSAMLWebApp.App_Start
{
    public class IdentityConfig
    {
        public static Saml2Configuration Saml2Configuration { get; private set; } = new Saml2Configuration();

        public static void RegisterIdentity()
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;

            Saml2Configuration.Issuer = ConfigurationManager.AppSettings["Saml2:Issuer"];
            Saml2Configuration.SignatureAlgorithm = ConfigurationManager.AppSettings["Saml2:SignatureAlgorithm"];
            Saml2Configuration.SignatureValidationCertificates.Add(CertificateUtil.Load(HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["Saml2:SignatureValidationCertificate"])));
            Saml2Configuration.CertificateValidationMode = (X509CertificateValidationMode)Enum.Parse(typeof(X509CertificateValidationMode), ConfigurationManager.AppSettings["Saml2:CertificateValidationMode"]);
            Saml2Configuration.RevocationMode = (X509RevocationMode)Enum.Parse(typeof(X509RevocationMode), ConfigurationManager.AppSettings["Saml2:RevocationMode"]);
            Saml2Configuration.AllowedAudienceUris.Add(Saml2Configuration.Issuer);
            Saml2Configuration.SingleSignOnDestination = new Uri(ConfigurationManager.AppSettings["Saml2:SingleSignOnDestination"]);
            Saml2Configuration.SingleLogoutDestination = new Uri(ConfigurationManager.AppSettings["Saml2:SingleLogoutDestination"]);
            Saml2Configuration.SignatureValidationCertificates.Add(CertificateUtil.Load(HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["Saml2:SignatureValidationCertificate"])));
        }
    }
}