// Synthetic static-analysis fixtures, never executed.
using System.Data.SqlClient;
using System.Diagnostics;

public class Fixtures
{
    public void Sql(string id, SqlConnection conn, AppDb db)
    {
        // ruleid: sql-built-from-strings
        var a = new SqlCommand("SELECT * FROM Employees WHERE Id = " + id, conn);
        // ruleid: sql-built-from-strings
        var b = new SqlCommand($"SELECT * FROM Employees WHERE Id = {id}", conn);
        var cmd = conn.CreateCommand();
        // ruleid: sql-built-from-strings
        cmd.CommandText = "DELETE FROM Leave WHERE Id = " + id;
        // ruleid: sql-built-from-strings
        db.Database.ExecuteSqlRaw($"UPDATE Payroll SET Approved = 1 WHERE Id = {id}");
        // ok: sql-built-from-strings
        var c = new SqlCommand("SELECT * FROM Employees WHERE Id = @id", conn);
        c.Parameters.AddWithValue("@id", id);
        // ok: sql-built-from-strings
        db.Employees.FromSqlInterpolated($"SELECT * FROM Employees WHERE Id = {id}");
        // ok: sql-built-from-strings
        db.Database.ExecuteSqlRaw("UPDATE Payroll SET Approved = 1 WHERE Id = {0}", id);
    }

    public void Shell(string host, ProcessStartInfo psi)
    {
        // ruleid: process-built-from-strings
        Process.Start("cmd.exe", "/c ping " + host);
        // ruleid: process-built-from-strings
        psi.Arguments = $"/c nslookup {host}";
        // ok: process-built-from-strings
        Process.Start("notepad.exe");
        // ok: process-built-from-strings
        psi.Arguments = "/c ipconfig";
    }

    public void Upload(HttpPostedFileBase file, IFormFile form, string folder)
    {
        // ruleid: upload-keeps-client-filename
        file.SaveAs(Server.MapPath("~/Uploads/" + file.FileName));
        // ruleid: upload-keeps-client-filename
        using var stream = new FileStream(Path.Combine(folder, form.FileName), FileMode.Create);
        // ok: upload-keeps-client-filename
        file.SaveAs(Server.MapPath("~/Uploads/" + Guid.NewGuid() + ".pdf"));
        // ok: upload-keeps-client-filename
        var display = form.FileName;
    }

    public void Secrets(Settings settings)
    {
        // ruleid: hardcoded-secret-in-code
        string password = "HrAdmin2024!"; // gitleaks:allow (deliberate fake for rule tests)
        // ruleid: hardcoded-secret-in-code
        settings.ApiKey = "a8f5f167f44f4964e6c998dee827110c"; // gitleaks:allow (deliberate fake for rule tests)
        // ruleid: hardcoded-secret-in-code
        var conn = new SqlConnection("Server=hrdb;Database=HRMIS;User Id=sa;Password=P@ssw0rd123;"); // gitleaks:allow (deliberate fake for rule tests)
        // ok: hardcoded-secret-in-code
        string label = "Password";
        // ok: hardcoded-secret-in-code
        var safe = new SqlConnection(Configuration.GetConnectionString("Hrmis"));
        // ok: hardcoded-secret-in-code
        var integrated = new SqlConnection("Server=hrdb;Database=HRMIS;Integrated Security=true;");
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        // ruleid: developer-error-page-outside-development
        app.UseDeveloperExceptionPage();
        if (env.IsDevelopment())
        {
            // ok: developer-error-page-outside-development
            app.UseDeveloperExceptionPage();
        }
    }
}
