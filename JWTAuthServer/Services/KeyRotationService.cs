
using JWTAuthServer.Data;
using JWTAuthServer.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace JWTAuthServer.Services
{
    public class KeyRotationService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly TimeSpan _rotationInterval = TimeSpan.FromDays(7); 

        public KeyRotationService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while(!stoppingToken.IsCancellationRequested)
            {
                await RotateKeysAsync();
                await Task.Delay(_rotationInterval, stoppingToken);
            }
        }
        private async Task RotateKeysAsync()
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var activeKey = await dbContext.SigningKeys.FirstOrDefaultAsync(k=>k.IsActive);
            if(activeKey == null || activeKey.ExpiresAt <= DateTime.UtcNow.AddDays(10)) 
            {
                if(activeKey != null)
                {
                    activeKey.IsActive = false;
                    dbContext.SigningKeys.Update(activeKey);
                }
                using var rsa = RSA.Create(2048);
                var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                var newKeyId = Guid.NewGuid().ToString();
                var newKey = new SigningKey
                {
                    KeyId = newKeyId,
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddYears(1) 
                };
                await dbContext.SigningKeys.AddAsync(newKey);
                await dbContext.SaveChangesAsync();
            }
        }
    }
}
