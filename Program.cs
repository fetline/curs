using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddAuthorization();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = AuthorizationOptions.ISSUER,
            ValidateAudience = true,
            ValidAudience = AuthorizationOptions.AUDIENCE,
            ValidateLifetime = true,
            IssuerSigningKey = AuthorizationOptions.GetSymmetricSecurityKey(),
            ValidateIssuerSigningKey = true,
        };
    });

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.MapPost("/encrypt", [Authorize] (TextRequest request, HttpContext context) =>
{
    var userEmail = context.User.Identity.Name;
    var encryptedText = AtbashCipher.Encrypt(request.Text);

    RequestHistoryStorage.History.Add(new RequestHistoryEntry
    {
        UserEmail = userEmail,
        RequestUrl = context.Request.Path,
        RequestTime = DateTime.UtcNow
    });

    return Results.Ok(new { encryptedText });
});

app.MapPost("/decrypt", [Authorize] (TextRequest request, HttpContext context) =>
{
    var userEmail = context.User.Identity.Name;
    var decryptedText = AtbashCipher.Decrypt(request.Text);

    RequestHistoryStorage.History.Add(new RequestHistoryEntry
    {
        UserEmail = userEmail,
        RequestUrl = context.Request.Path,
        RequestTime = DateTime.UtcNow
    });

    return Results.Ok(new { decryptedText });
});

app.MapPost("/login", (Person loginData) =>
{
    bool auth = false;
    using (var connection = new SqliteConnection("Data source = /home/wender/Документы/curs/user_DB.db"))
    {
        connection.Open();
        string sqlExpression = "SELECT email, password FROM users WHERE email = @Email AND password = @Password";
        SqliteCommand command = new SqliteCommand(sqlExpression, connection);
        command.Parameters.AddWithValue("@Email", loginData.Email);
        command.Parameters.AddWithValue("@Password", loginData.Password);
        using (SqliteDataReader reader = command.ExecuteReader())
        {
            if (reader.HasRows)
            {
                auth = true;
            }
        }
    }

    if (!auth)
    {
        return Results.Unauthorized();
    }

    var claims = new List<Claim> { new Claim(ClaimTypes.Name, loginData.Email) };
    var jwt = new JwtSecurityToken(
        issuer: AuthorizationOptions.ISSUER,
        audience: AuthorizationOptions.AUDIENCE,
        claims: claims,
        expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
        signingCredentials: new SigningCredentials(AuthorizationOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256)
    );
    var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

    var response = new
    {
        access_token = encodedJwt,
        username = loginData.Email
    };

    return Results.Json(response);
});

app.MapGet("/data", [Authorize] (HttpContext context) =>
{
    var userEmail = context.User.Identity.Name;

    RequestHistoryStorage.History.Add(new RequestHistoryEntry
    {
        UserEmail = userEmail,
        RequestUrl = context.Request.Path,
        RequestTime = DateTime.UtcNow
    });

    return new { message = "Hello World!" };
});

app.MapGet("/request-history", [Authorize] (HttpContext context) =>
{
    var userEmail = context.User.Identity.Name;

    var userHistory = RequestHistoryStorage.History
        .Where(entry => entry.UserEmail == userEmail)
        .OrderByDescending(entry => entry.RequestTime)
        .Select(entry => new
        {
            entry.RequestUrl,
            entry.RequestTime
        })
        .ToList();

    return Results.Json(userHistory);
});

app.MapDelete("/request-history", [Authorize] (HttpContext context) =>
{
    var userEmail = context.User.Identity.Name;

    RequestHistoryStorage.History.RemoveAll(entry => entry.UserEmail == userEmail);

    return Results.Ok(new { message = "History cleared successfully." });
});

app.MapPatch("/change-password", [Authorize] (ChangePasswordRequest changePasswordRequest, HttpContext context) =>
{
    var userEmail = context.User.Identity.Name;

    bool isCurrentPasswordValid = false;
    using (var connection = new SqliteConnection("Data source = /home/wender/Документы/curs/user_DB.db"))
    {
        connection.Open();
        string sqlExpression = "SELECT password FROM users WHERE email = @Email AND password = @CurrentPassword";
        SqliteCommand command = new SqliteCommand(sqlExpression, connection);
        command.Parameters.AddWithValue("@Email", userEmail);
        command.Parameters.AddWithValue("@CurrentPassword", changePasswordRequest.CurrentPassword);
        using (SqliteDataReader reader = command.ExecuteReader())
        {
            if (reader.HasRows)
            {
                isCurrentPasswordValid = true;
            }
        }
    }

    if (!isCurrentPasswordValid)
    {
        return Results.BadRequest(new { message = "Current password is incorrect." });
    }

    using (var connection = new SqliteConnection("Data source = /home/wender/Документы/curs/user_DB.db"))
    {
        connection.Open();
        string sqlExpression = "UPDATE users SET password = @NewPassword WHERE email = @Email";
        SqliteCommand command = new SqliteCommand(sqlExpression, connection);
        command.Parameters.AddWithValue("@Email", userEmail);
        command.Parameters.AddWithValue("@NewPassword", changePasswordRequest.NewPassword);
        command.ExecuteNonQuery();
    }

    var claims = new List<Claim> { new Claim(ClaimTypes.Name, userEmail) };
    var jwt = new JwtSecurityToken(
        issuer: AuthorizationOptions.ISSUER,
        audience: AuthorizationOptions.AUDIENCE,
        claims: claims,
        expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
        signingCredentials: new SigningCredentials(AuthorizationOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256)
    );
    var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

    var response = new
    {
        access_token = encodedJwt,
        username = userEmail
    };

    return Results.Json(response);
});

app.MapPost("/text", [Authorize] (TextResource textResource, HttpContext context) =>
{
    var userEmail = context.User.Identity.Name;

    using (var connection = new SqliteConnection("Data source = /home/wender/Документы/curs/user_DB.db"))
    {
        connection.Open();
        string sqlExpression = "INSERT INTO text_resources (content, user_email) VALUES (@Content, @UserEmail)";
        SqliteCommand command = new SqliteCommand(sqlExpression, connection);
        command.Parameters.AddWithValue("@Content", textResource.Content);
        command.Parameters.AddWithValue("@UserEmail", userEmail);
        command.ExecuteNonQuery();
    }

    RequestHistoryStorage.History.Add(new RequestHistoryEntry
    {
        UserEmail = userEmail,
        RequestUrl = context.Request.Path,
        RequestTime = DateTime.UtcNow
    });

    return Results.Ok(new { message = "Text resource added successfully." });
});


app.MapPatch("/text/{id}", [Authorize] (int id, TextResource textResource, HttpContext context) =>
{
    var userEmail = context.User.Identity.Name;

    using (var connection = new SqliteConnection("Data source = /home/wender/Документы/curs/user_DB.db"))
    {
        connection.Open();
        string sqlExpression = "UPDATE text_resources SET content = @Content WHERE id = @Id AND user_email = @UserEmail";
        SqliteCommand command = new SqliteCommand(sqlExpression, connection);
        command.Parameters.AddWithValue("@Content", textResource.Content);
        command.Parameters.AddWithValue("@Id", id);
        command.Parameters.AddWithValue("@UserEmail", userEmail);
        int rowsAffected = command.ExecuteNonQuery();

        if (rowsAffected == 0)
        {
            return Results.NotFound(new { message = "Text resource not found or you do not have permission to edit it." });
        }
    }

    RequestHistoryStorage.History.Add(new RequestHistoryEntry
    {
        UserEmail = userEmail,
        RequestUrl = context.Request.Path,
        RequestTime = DateTime.UtcNow
    });

    return Results.Ok(new { message = "Text resource updated successfully." });
});

app.MapDelete("/text/{id}", [Authorize] (int id, HttpContext context) =>
{
    var userEmail = context.User.Identity.Name;

    using (var connection = new SqliteConnection("Data source = /home/wender/Документы/curs/user_DB.db"))
    {
        connection.Open();
        string sqlExpression = "DELETE FROM text_resources WHERE id = @Id AND user_email = @UserEmail";
        SqliteCommand command = new SqliteCommand(sqlExpression, connection);
        command.Parameters.AddWithValue("@Id", id);
        command.Parameters.AddWithValue("@UserEmail", userEmail);
        int rowsAffected = command.ExecuteNonQuery();

        if (rowsAffected == 0)
        {
            return Results.NotFound(new { message = "Text resource not found or you do not have permission to delete it." });
        }
    }

    RequestHistoryStorage.History.Add(new RequestHistoryEntry
    {
        UserEmail = userEmail,
        RequestUrl = context.Request.Path,
        RequestTime = DateTime.UtcNow
    });

    return Results.Ok(new { message = "Text resource deleted successfully." });
});

app.MapGet("/texts", [Authorize] (HttpContext context) => 
{
    var userEmail = context.User.Identity.Name;

    var texts = new List<TextResource>();
    using (var connection = new SqliteConnection("Data source = /home/wender/Документы/curs/user_DB.db"))
    {
        connection.Open();
        string sqlExpression = "SELECT id, content FROM text_resources WHERE user_email = @UserEmail";
        SqliteCommand command = new SqliteCommand(sqlExpression, connection);
        command.Parameters.AddWithValue("@UserEmail", userEmail);

        using (SqliteDataReader reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                var textResource = new TextResource
                {
                    Id = reader.GetInt32(0),
                    Content = reader.GetString(1),
                    UserEmail = userEmail
                };
                texts.Add(textResource);
            }
        }
    }

    return Results.Json(texts);
});

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

app.Run();

public static class AtbashCipher
{
    private static readonly Dictionary<char, char> _atbashMap = new Dictionary<char, char>
    {
        {'A', 'Z'}, {'B', 'Y'}, {'C', 'X'}, {'D', 'W'}, {'E', 'V'},
        {'F', 'U'}, {'G', 'T'}, {'H', 'S'}, {'I', 'R'}, {'J', 'Q'},
        {'K', 'P'}, {'L', 'O'}, {'M', 'N'}, {'N', 'M'}, {'O', 'L'},
        {'P', 'K'}, {'Q', 'J'}, {'R', 'I'}, {'S', 'H'}, {'T', 'G'},
        {'U', 'F'}, {'V', 'E'}, {'W', 'D'}, {'X', 'C'}, {'Y', 'B'},
        {'Z', 'A'},
        {'a', 'z'}, {'b', 'y'}, {'c', 'x'}, {'d', 'w'}, {'e', 'v'},
        {'f', 'u'}, {'g', 't'}, {'h', 's'}, {'i', 'r'}, {'j', 'q'},
        {'k', 'p'}, {'l', 'o'}, {'m', 'n'}, {'n', 'm'}, {'o', 'l'},
        {'p', 'k'}, {'q', 'j'}, {'r', 'i'}, {'s', 'h'}, {'t', 'g'},
        {'u', 'f'}, {'v', 'e'}, {'w', 'd'}, {'x', 'c'}, {'y', 'b'},
        {'z', 'a'}
    };

    public static string Encrypt(string text)
    {
        return new string(
            text.Select(c => _atbashMap.TryGetValue(c, out var mapped) ? mapped : c)
                .ToArray()
        );
    }

    public static string Decrypt(string text)
    {
        return Encrypt(text); // Atbash - симметричный шифр
    }
}
// Класс для запроса текста
public class TextRequest
{
    public string Text { get; set; }
}

// Классы для хранения истории запросов
public static class RequestHistoryStorage
{
    public static List<RequestHistoryEntry> History { get; } = new List<RequestHistoryEntry>();
}

public class RequestHistoryEntry
{
    public string UserEmail { get; set; }
    public string RequestUrl { get; set; }
    public DateTime RequestTime { get; set; }
}

public class AuthorizationOptions
{
    public const string ISSUER = "MyAuthServer";
    public const string AUDIENCE = "MyAuthClient";
    const string KEY = "mysupersecret_secretsecretsecret!123";
    public static SymmetricSecurityKey GetSymmetricSecurityKey() =>
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(KEY));
}

public class Person
{
    public required string Email { get; set; }
    public required string Password { get; set; }
}

public class ChangePasswordRequest
{
    public required string CurrentPassword { get; set; }
    public required string NewPassword { get; set; }
}

public class TextResource
{
    public int Id { get; set; }
    public string Content { get; set; }
    public string UserEmail { get; set; }
}