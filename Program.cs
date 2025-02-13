using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using FreshFarmMarket.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Diagnostics;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddRazorPages();

// Configure database context
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString"))
);

// Configure Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 12;
    options.Password.RequiredUniqueChars = 1;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;

    // SignIn settings
    options.SignIn.RequireConfirmedEmail = false; // Disabling email verification for login
    options.SignIn.RequireConfirmedAccount = false; // Disabling account confirmation
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders();

// Configure cookie settings for authentication
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/Error?statusCode=403"; // Redirect 403 errors to error page
    options.SlidingExpiration = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// Configure session
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// Add HSTS and HTTPS configuration for production environments
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(60);
});

// Configure anti-forgery tokens for extra security
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.HttpOnly = true;
});

// Build the application
var app = builder.Build();

// Get the logger service
var logger = app.Services.GetRequiredService<ILogger<Program>>();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    // Log and handle general exceptions
    app.UseExceptionHandler(errorApp =>
    {
        errorApp.Run(async context =>
        {
            var exceptionFeature = context.Features.Get<IExceptionHandlerPathFeature>();
            if (exceptionFeature != null)
            {
                logger.LogError($"Unhandled Exception: {exceptionFeature.Error.Message}");
                logger.LogError($"Exception Details: {exceptionFeature.Error.StackTrace}");
            }
            context.Response.Redirect("/Error");
        });
    });

    // Log and handle specific HTTP status errors (404, 403, etc.)
    app.UseStatusCodePagesWithReExecute("/Error", "?statusCode={0}");
    app.UseHsts();
}

// Middleware pipeline
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    // Map Razor Pages
    endpoints.MapRazorPages();

    // Redirect root URL ("/") based on authentication status
    endpoints.MapGet("/", async context =>
    {
        if (!context.User.Identity.IsAuthenticated)
        {
            logger.LogInformation("User is not authenticated, redirecting to /Login");
            context.Response.Redirect("/Login");
        }
        else
        {
            logger.LogInformation("User is authenticated, redirecting to /Home");
            context.Response.Redirect("/Home");
        }
        await Task.CompletedTask;
    });

    // Fallback for any unmatched routes (redirects to error page with 404 code)
    endpoints.MapFallback(async context =>
    {
        logger.LogWarning("Unmatched route: {Route}. Redirecting to /Error?statusCode=404", context.Request.Path.Value);

        context.Response.Redirect("/Error?statusCode=404");
        await Task.CompletedTask;
    });
});

// Log database migrations and initialization
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<AuthDbContext>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        context.Database.Migrate();  // Apply any migrations
        logger.LogInformation("Database migration completed successfully.");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "An error occurred while migrating or initializing the database.");
    }
}

// Log requests to the error page
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/Error"))
    {
        var statusCode = context.Request.Query["statusCode"];
        if (int.TryParse(statusCode, out int parsedStatusCode))
        {
            logger.LogWarning("User redirected to Error page. Status Code: {StatusCode}", parsedStatusCode);
        }
        else
        {
            logger.LogWarning("User redirected to Error page with an invalid status code.");
        }

    }
    await next();
});

// Run the application
app.Run();
