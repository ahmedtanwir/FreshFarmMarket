using FreshFarmMarket.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using FreshFarmMarket.Pages.Shared;

namespace FreshFarmMarket.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IConfiguration _configuration;

        // Binding properties for the form
        [BindProperty]
        [Required(ErrorMessage = "Full Name is required.")]
        [StringLength(100, ErrorMessage = "Full Name cannot be longer than 100 characters.")]
        public string FullName { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Credit Card Number is required.")]
        [StringLength(16, MinimumLength = 16, ErrorMessage = "Credit Card number should be between 16 digits.")]
        public string CreditCardNo { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Gender is required.")]
        public string Gender { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Mobile Number is required.")]
        [Phone(ErrorMessage = "Invalid Mobile Number.")]
        public string MobileNo { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Delivery Address is required.")]
        public string DeliveryAddress { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string Email { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long.")]
        public string Password { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Confirm Password is required.")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "About Me is required.")]
        [StringLength(500, ErrorMessage = "About Me section cannot exceed 500 characters.")]
        public string AboutMe { get; set; }

        [BindProperty]
        [Required(ErrorMessage = "Please upload a photo.")]
        [DataType(DataType.Upload)]
        [ImageFile(new[] { ".jpg", ".jpeg", ".png" }, new[] { "image/jpeg", "image/png" }, ErrorMessage = "Only JPG, JPEG, or PNG files are allowed.")]
        public IFormFile Photo { get; set; }

        // Inject necessary services via the constructor
        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<RegisterModel> logger, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _configuration = configuration; // Access secure configuration
        }

        // OnGet method to display the page if the user is not authenticated
        public void OnGet()
        {
            if (User.Identity.IsAuthenticated)
            {
                Response.Redirect("/Index");  // Redirect to homepage if already logged in
            }
        }

        // OnPostAsync method for form submission and validation
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();  // Return the page with validation errors if invalid
            }

            // Check if email already exists in the system
            var existingUser = await _userManager.FindByEmailAsync(Email);
            if (existingUser != null)
            {
                ModelState.AddModelError(string.Empty, "This email is already registered.");
                return Page();  // Return the page if the email already exists
            }

            // Process file upload (handle the photo)
            string photoPath = null;
            if (Photo != null && Photo.Length > 0)
            {
                const long maxFileSize = 5 * 1024 * 1024; // 5 MB
                if (Photo.Length > maxFileSize)
                {
                    ModelState.AddModelError(string.Empty, "The file size exceeds the 5MB limit.");
                    return Page();
                }

                var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");
                if (!Directory.Exists(uploadsFolder))
                {
                    Directory.CreateDirectory(uploadsFolder);
                }

                var uniqueFileName = $"{Path.GetFileNameWithoutExtension(Photo.FileName)}_{Path.GetRandomFileName()}{Path.GetExtension(Photo.FileName)}";
                photoPath = Path.Combine("uploads", uniqueFileName);

                var filePath = Path.Combine(uploadsFolder, uniqueFileName);
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await Photo.CopyToAsync(stream);
                }
            }

            // Encrypt the Credit Card Number
            var encryptedCreditCardNo = EncryptCreditCardNumber(CreditCardNo);

            // Generate random key and IV for encryption (used for decryption later)
            var key = GenerateRandomBytes(32);  // 32 bytes for AES-256 key
            var iv = GenerateRandomBytes(16);   // 16 bytes for AES block size

            // Base64 encode the AES Key and IV before saving them
            var encodedKey = Convert.ToBase64String(key); // Encode key
            var encodedIv = Convert.ToBase64String(iv);   // Encode IV

            // Store encrypted credit card and its encryption details
            var user = new ApplicationUser
            {
                UserName = Email,
                Email = Email,
                FullName = FullName,
                AboutMe = AboutMe,
                ProfilePhotoPath = photoPath,
                Gender = Gender,
                MobileNo = MobileNo,
                DeliveryAddress = DeliveryAddress,
                CreditCardNo = encryptedCreditCardNo,  // Save encrypted credit card number
                EncryptionKey = encodedKey,            // Save the AES Key (Base64 encoded)
                EncryptionIV = encodedIv              // Save the AES IV (Base64 encoded)
            };

            var result = await _userManager.CreateAsync(user, Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("User created successfully.");
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToPage("Index");  // Redirect to home page on success
            }

            // If creation fails, add errors to ModelState and return to the page
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }

        // Encrypt Credit Card Number
        private string EncryptCreditCardNumber(string creditCardNumber)
        {
            var key = GenerateRandomBytes(32); // 32 bytes for AES-256 key
            var iv = GenerateRandomBytes(16);  // 16 bytes for AES block size

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(creditCardNumber);
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        // Helper method to generate random bytes
        private byte[] GenerateRandomBytes(int size)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] randomBytes = new byte[size];
                rng.GetBytes(randomBytes);
                return randomBytes;
            }
        }
    }
}