using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace API.Dtos
{
    public class ForgotPasswordDto
    {   
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
}