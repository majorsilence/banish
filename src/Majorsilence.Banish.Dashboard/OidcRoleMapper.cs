using System.Security.Claims;
using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Dashboard;

/// <summary>Maps the role/group claim from an OpenID Connect provider to Banish roles.</summary>
public static class OidcRoleMapper
{
    /// <summary>
    /// Admin wins over viewer; a user matching neither gets no role and therefore no access.
    /// Comparison ignores case.
    /// </summary>
    public static IReadOnlyList<string> Map(IEnumerable<Claim> claims, OidcOptions options)
    {
        var values = claims.Where(c => c.Type == options.RoleClaim)
            .SelectMany(c => ExpandValue(c.Value))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (options.AdminRoles.Any(values.Contains))
        {
            return [ApiRoles.Admin];
        }

        return options.ViewerRoles.Any(values.Contains) ? [ApiRoles.Viewer] : [];
    }

    // Some providers send an array as one JSON string.
    private static IEnumerable<string> ExpandValue(string value)
    {
        if (value.StartsWith('['))
        {
            try
            {
                return System.Text.Json.JsonSerializer.Deserialize<string[]>(value) ?? [value];
            }
            catch (System.Text.Json.JsonException)
            {
            }
        }

        return [value];
    }
}
