import unittest

from vaptkit.aspnet_routes import review_aspnet


def run(files: dict[str, str], **kwargs) -> dict[tuple[str, str], dict]:
    routes = review_aspnet(files.__getitem__, set(files), **kwargs)
    return {(route["handlers"][0]["method"], route["path"]): route["handlers"][0] for route in routes}


EMPLOYEES = '''
[ApiController]
[Route("api/[controller]")]
public class EmployeesController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult Get(int id) { if (id > 0) { return Ok(); } return NotFound(); }

    [HttpPost]
    [Authorize(Roles = "HR")]
    public IActionResult Create(Employee employee) => Ok();

    [HttpDelete("{id}")]
    [Authorize]
    public IActionResult Delete(int id) => Ok();

    private void Helper() { }
}
'''


class ControllerTests(unittest.TestCase):
    def test_actions_without_authorize_are_unauthenticated_and_routes_are_built(self):
        handlers = run({"Controllers/EmployeesController.cs": EMPLOYEES})
        self.assertEqual(set(handlers), {("GET", "/api/Employees/{id}"), ("POST", "/api/Employees"),
                                         ("DELETE", "/api/Employees/{id}")})
        self.assertFalse(handlers[("GET", "/api/Employees/{id}")]["authentication"])
        self.assertTrue(handlers[("POST", "/api/Employees")]["authorization"])
        self.assertTrue(handlers[("DELETE", "/api/Employees/{id}")]["authentication"])
        self.assertFalse(handlers[("DELETE", "/api/Employees/{id}")]["authorization"])

    def test_controller_level_and_inherited_authorize_protect_actions(self):
        handlers = run({
            "Controllers/BaseHrController.cs": '[Authorize]\npublic abstract class BaseHrController : Controller { }',
            "Controllers/PayrollController.cs": '''
public class PayrollController : BaseHrController
{
    public ActionResult Index() { return View(); }
    [AllowAnonymous]
    public ActionResult Help() { return View(); }
}''',
        })
        self.assertTrue(handlers[("ANY", "/Payroll/Index")]["authentication"])
        self.assertTrue(handlers[("ANY", "/Payroll/Help")]["public"])

    def test_custom_authorize_attributes_count_as_role_checks(self):
        handlers = run({"Controllers/AdminController.cs": '''
[CustomAuthorize(Roles = "Admin")]
public class AdminController : Controller
{
    public ActionResult Users() => View();
}'''})
        self.assertTrue(handlers[("ANY", "/Admin/Users")]["authentication"])
        self.assertTrue(handlers[("ANY", "/Admin/Users")]["authorization"])

    def test_global_authorize_filter_protects_everything(self):
        handlers = run({
            "App_Start/FilterConfig.cs": "public class FilterConfig { public static void Register(GlobalFilterCollection filters) { filters.Add(new AuthorizeAttribute()); } }",
            "Controllers/EmployeesController.cs": EMPLOYEES,
        })
        self.assertTrue(all(handler["authentication"] for handler in handlers.values()))

    def test_route_template_braces_and_commented_attributes_do_not_confuse_parsing(self):
        handlers = run({"Controllers/LeaveController.cs": '''
[Route("api/leave")]
public class LeaveController : ControllerBase
{
    [HttpGet("{year}/{month}")]
    public IActionResult Month(int year, int month) { var x = "}{"; return Ok(x); }
    [HttpGet("summary")]
    public IActionResult Summary() => Ok();
}'''})
        self.assertEqual(set(handlers), {("GET", "/api/leave/{year}/{month}"), ("GET", "/api/leave/summary")})

    def test_test_projects_are_ignored(self):
        self.assertEqual(run({"Hrmis.Tests/FakeController.cs": EMPLOYEES}), {})


class MinimalApiTests(unittest.TestCase):
    def test_require_authorization_after_a_lambda_body_and_on_groups(self):
        handlers = run({"Program.cs": '''
var app = builder.Build();
app.MapGet("/health", () => "ok");
app.MapPost("/payslips", (Payslip p) => { Save(p); return Results.Ok(); }).RequireAuthorization();
var hr = app.MapGroup("/hr").RequireAuthorization("HrOnly");
hr.MapDelete("/employees/{id}", (int id) => Results.Ok());
app.MapGet("/public", () => "hi").AllowAnonymous();
'''})
        self.assertFalse(handlers[("GET", "/health")]["authentication"])
        self.assertTrue(handlers[("POST", "/payslips")]["authentication"])
        self.assertTrue(handlers[("DELETE", "/hr/employees/{id}")]["authentication"])
        self.assertTrue(handlers[("GET", "/public")]["public"])

    def test_fallback_policy_protects_minimal_apis(self):
        handlers = run({"Program.cs": '''
builder.Services.AddAuthorization(o => o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
app.MapGet("/me", () => "ok");
'''})
        self.assertTrue(handlers[("GET", "/me")]["authentication"])


class InlineChecksTests(unittest.TestCase):
    def test_permission_checks_inside_the_action_body_count(self):
        handlers = run({"Controllers/ReportsController.cs": '''
public class ReportsController : Controller
{
    public async Task<IActionResult> Salaries()
    {
        if (!User.IsInRole("Payroll")) return Forbid();
        return View();
    }
    public IActionResult Export() => File(Build(), "text/csv");
}'''})
        self.assertTrue(handlers[("ANY", "/Reports/Salaries")]["authentication"])
        self.assertTrue(handlers[("ANY", "/Reports/Salaries")]["authorization"])
        self.assertFalse(handlers[("ANY", "/Reports/Export")]["authentication"])

    def test_authorize_attribute_on_a_minimal_api_lambda(self):
        handlers = run({"Endpoints/Create.cs": '''
app.MapPost("api/catalog-items",
    [Authorize(Roles = Roles.Admin)] async (CreateItem request) => { await Save(request); return Results.Ok(); });
'''})
        self.assertTrue(handlers[("POST", "/api/catalog-items")]["authentication"])
        self.assertTrue(handlers[("POST", "/api/catalog-items")]["authorization"])
