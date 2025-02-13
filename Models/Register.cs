using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;  // Required for IFormFile

namespace FreshFarmMarket.Models
{
    public class Register
    {
        [Required(ErrorMessage = "Full Name is required.")]
        [StringLength(100, ErrorMessage = "Full Name cannot be longer than 100 characters.")]
        public string FullName { get; set; }

        // Credit Card Number (Sensitive Data, should be encrypted before saving)
        [Required(ErrorMessage = "Credit Card Number is required.")]
        [CreditCard(ErrorMessage = "Invalid Credit Card Number.")]
        public string CreditCardNo { get; set; }  // Credit Card (Needs encryption)

        // Gender (Make sure to use radio buttons or dropdown in the UI)
        [Required(ErrorMessage = "Gender is required.")]
        public string Gender { get; set; }  // Gender field

        // Mobile Number (Required field)
        [Required(ErrorMessage = "Mobile Number is required.")]
        [Phone(ErrorMessage = "Invalid Phone Number.")]
        public string MobileNo { get; set; }  // Mobile Number field

        // Delivery Address
        [Required(ErrorMessage = "Delivery Address is required.")]
        [StringLength(500, ErrorMessage = "Delivery Address cannot be longer than 500 characters.")]
        public string DeliveryAddress { get; set; }  // Delivery Address field

        // Email Address
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string Email { get; set; }

        // Password field (with strength check)
        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long.")]
        public string Password { get; set; }

        // Confirm Password
        [Required(ErrorMessage = "Confirm Password is required.")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        // About Me (textarea)
        [Required(ErrorMessage = "About Me is required.")]
        [StringLength(500, ErrorMessage = "About Me section cannot exceed 500 characters.")]
        public string AboutMe { get; set; }

        // Photo Upload (only allows .jpg, .jpeg, or .png)
        [Required(ErrorMessage = "Please upload a photo.")]
        [DataType(DataType.Upload)]  // Optional, helps indicate this is a file
        [FileExtensions(Extensions = "jpg,jpeg,png", ErrorMessage = "Only JPG, JPEG, or PNG files are allowed.")]
        public IFormFile Photo { get; set; }

        // You can include more properties depending on your specific requirements
    }
}
