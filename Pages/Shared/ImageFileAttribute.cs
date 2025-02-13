using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Linq;

namespace FreshFarmMarket.Pages.Shared
{
    public class ImageFileAttribute : ValidationAttribute
    {
        private readonly string[] _extensions;
        private readonly string[] _mimeTypes;

        public ImageFileAttribute(string[] extensions, string[] mimeTypes)
        {
            _extensions = extensions;
            _mimeTypes = mimeTypes;
        }

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            var file = value as IFormFile;

            if (file == null || file.Length == 0)
            {
                return new ValidationResult("Please upload a photo.");
            }

            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (!_extensions.Contains(extension))
            {
                return new ValidationResult($"Only {string.Join(", ", _extensions)} files are allowed.");
            }

            // Check MIME type 
            if (!_mimeTypes.Contains(file.ContentType))
            {
                return new ValidationResult("Invalid file type.");
            }

            return ValidationResult.Success;
        }
    }
}