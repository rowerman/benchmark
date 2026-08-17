using System.Text;
using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var connectionString = builder.Configuration["DB_CONNECTION"]
    ?? throw new InvalidOperationException("DB_CONNECTION is required");

app.MapGet("/", () => Results.Content(
    "<!doctype html><title>Inventory Search</title><form action=\"/search\" method=\"get\"><input name=\"q\" placeholder=\"Search products\"><button type=\"submit\">Search</button></form>",
    "text/html"));

app.MapGet("/search", async (string q) =>
{
    await using var connection = new SqlConnection(connectionString);
    await connection.OpenAsync();

    await using (var setup = connection.CreateCommand())
    {
        setup.CommandText = "IF OBJECT_ID(N'dbo.products', N'U') IS NULL BEGIN CREATE TABLE dbo.products (id INT IDENTITY PRIMARY KEY, name NVARCHAR(100) NOT NULL); INSERT INTO dbo.products (name) VALUES (N'widget'), (N'gadget'); END";
        await setup.ExecuteNonQueryAsync();
    }

    // Intentionally vulnerable benchmark sink: q is concatenated into executable T-SQL.
    var sql = $"SELECT name FROM dbo.products WHERE name LIKE '%{q}%'";
    var output = new StringBuilder();
    await using var command = new SqlCommand(sql, connection);
    await using var reader = await command.ExecuteReaderAsync();
    do
    {
        while (await reader.ReadAsync())
        {
            for (var column = 0; column < reader.FieldCount; column++)
            {
                output.Append(reader.IsDBNull(column) ? string.Empty : reader.GetValue(column)).Append(' ');
            }
            output.AppendLine();
        }
    } while (await reader.NextResultAsync());

    return Results.Content($"<pre>{System.Net.WebUtility.HtmlEncode(output.ToString())}</pre>", "text/html");
});

app.Run();
