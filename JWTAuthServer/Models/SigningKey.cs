using System.ComponentModel.DataAnnotations;

namespace JWTAuthServer.Models
{
    public class SigningKey
    {
        [Key]
        public int Id { get; set; }
        [Required]
        [MaxLength(100)]
        public string KeyId { get; set; }
        [Required]
        public string PrivateKey { get; set; }
        [Required]
        public string PublicKey { get; set; }
        [Required]
        public bool IsActive { get; set; }
        [Required]
        public DateTime CreatedAt { get; set; }
        [Required]
        public DateTime ExpiresAt { get; set; }
    }
}
