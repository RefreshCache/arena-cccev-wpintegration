<%@ WebService Language="C#" Class="AuthenticationService" %>

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

        bool foundRoleMatch = false;
        RoleCollection arenaRoles = new RoleCollection();
        arenaRoles.LoadByPersonId(organizationID, personID);

        foreach (var role in roles)
        {
            foreach (var r in arenaRoles)
            {
                foundRoleMatch = role.Trim().ToLower() == r.RoleName.ToLower();
            }

            if (foundRoleMatch)
            {
                break;
            }
        }
        
        if (personID != Constants.NULL_INT && foundRoleMatch)
        {
            var person = new Person(personID);
            return GetWPUser(person);
        }

        return null;
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