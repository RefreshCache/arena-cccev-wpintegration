<%@ WebService Language="C#" Class="AuthenticationService" %>

using System.Linq;
using System.Web.Script.Services;
using System.Web.Services;
using System.Xml.Serialization;
using Arena.Core;
using Arena.Custom.Cccev.DataUtils;
using Arena.Custom.Cccev.WebUtils.Entity;
using Arena.Portal;
using Arena.Security;

[WebService(Namespace = "http://localhost/Arena")]
[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
[ScriptService]
[XmlInclude(typeof(WordPressUser))]
public class AuthenticationService  : WebService 
{
    [WebMethod(EnableSession = true)]
    [ScriptMethod(ResponseFormat = ResponseFormat.Json)]
    public object AuthenticateWP(string username, string password, string ipAddress, string securityRoles, string orgID)
    {
        int organizationID = int.Parse(orgID);
        var roles = securityRoles.Split(new[] { ',' });
        var personID = PortalLogin.Authenticate(username, password, ipAddress, organizationID);

        if (personID != Constants.NULL_INT && roles.Length == 0)
        {
            return GetWPUser(new Person(personID));
        }
        
        bool foundRoleMatch = false;
        RoleCollection arenaRoles = new RoleCollection();
        arenaRoles.LoadByPersonId(organizationID, personID);
        
        foreach (var r in roles)
        {
            var role = r;
            foundRoleMatch = arenaRoles.Any(ar => ar.RoleName.Trim().ToLower() == role.Trim().ToLower());

            if (foundRoleMatch)
            {
                break;
            }
        }

        return (personID != Constants.NULL_INT && foundRoleMatch) ? GetWPUser(new Person(personID)) : null;
    }

    private static object GetWPUser(Person person)
    {
        return new WordPressUser
                   {
                       FirstName = person.FirstName,
                       LastName = person.LastName,
                       DisplayName = person.FullName,
                       Email = person.Emails.FirstActive
                   };
    }
}