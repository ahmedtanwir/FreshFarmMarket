using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using FreshFarmMarket.Models;

namespace FreshFarmMarket.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;

        // Constructor to inject SignInManager and Logger
        public LogoutModel(SignInManager<ApplicationUser> signInManager, ILogger<LogoutModel> logger)
        {
            _signInManager = signInManager;
            _logger = logger;
        }

        // This handler is invoked when the POST request is made to logout
        public async Task<IActionResult> OnPostAsync()
        {
            await _signInManager.SignOutAsync();  // Log the user out
            _logger.LogInformation("User logged out.");

            // After logout, redirect the user to the home page or login page
            return RedirectToPage("/Index");  // Change the redirect URL if needed
        }
    }
}
