using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Logging;
using FreshFarmMarket.Models;
using Microsoft.AspNetCore.Authentication;
using System.Net.Http;
using System.Text.Json;
using System.Collections.Generic;

namespace FreshFarmMarket.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<LoginModel> _logger;

        [BindProperty]
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [BindProperty]
        public bool RememberMe { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        [BindProperty]
        public string RecaptchaToken { get; set; } // Added reCAPTCHA token

        private const string RecaptchaSecretKey = "6LeRwtUqAAAAAOn5ZNJbNw7H8hSiAC2nY7Oh0JaJ"; // Replace with your Google reCAPTCHA secret key

        public LoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            if (User.Identity.IsAuthenticated)
            {
                return RedirectToPage("/Index");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Validate reCAPTCHA first
            bool isRecaptchaValid = await ValidateRecaptcha(RecaptchaToken);
            if (!isRecaptchaValid)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
                return Page(); // Stop login attempt if reCAPTCHA is invalid
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return Page();
            }

            // Attempt to sign in
            var result = await _signInManager.PasswordSignInAsync(user.UserName,
                Password, RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} logged in successfully", Email);
                return LocalRedirect(returnUrl);
            }

            if (result.RequiresTwoFactor)
            {
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = RememberMe });
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User {Email} account locked out", Email);
                ModelState.AddModelError(string.Empty, "Account has been locked out. Please try again later.");
                return Page();
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }

        public async Task<IActionResult> OnPostLogoutAsync()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return RedirectToPage("/Index");
        }

        /// <summary>
        /// Validates the reCAPTCHA response token with Google.
        /// </summary>
        private async Task<bool> ValidateRecaptcha(string recaptchaToken)
        {
            if (string.IsNullOrEmpty(recaptchaToken))
            {
                _logger.LogWarning("reCAPTCHA token is missing.");
                return false;
            }

            using var httpClient = new HttpClient();
            var response = await httpClient.PostAsync(
                "https://www.google.com/recaptcha/api/siteverify",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
            { "secret", RecaptchaSecretKey },
            { "response", recaptchaToken }
                })
            );

            var json = await response.Content.ReadAsStringAsync();
            using var jsonDoc = JsonDocument.Parse(json);

            if (!jsonDoc.RootElement.TryGetProperty("success", out JsonElement successElement) || !successElement.GetBoolean())
            {
                _logger.LogWarning("reCAPTCHA validation failed. Response: {0}", json);
                return false;
            }

            // Check if "score" exists before using it
            double score = 0.0;
            if (jsonDoc.RootElement.TryGetProperty("score", out JsonElement scoreElement))
            {
                score = scoreElement.GetDouble();
            }
            else
            {
                _logger.LogWarning("reCAPTCHA response is missing 'score'. Full response: {0}", json);
            }

            _logger.LogInformation("reCAPTCHA success: {0}, score: {1}", successElement.GetBoolean(), score);

            return score > 0.5; // Adjust threshold as needed
        }

    }
}
