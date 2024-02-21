using Application.Interface;
using Application.Mapping;
using Domain.Admin;
using Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using AutoMapper;
using Microsoft.Extensions.DependencyInjection;
using Application.Interface.Repository;
using Infrastructure.Repository;

namespace API.Extensions
{
    public static class ServiceExtensions
    {
        public static IServiceCollection AddService(this IServiceCollection services, IConfiguration config) 
        {
            services.AddHttpContextAccessor();

            //Setup Services
            services.AddScoped<UserManager<AppUser>>();
            services.AddScoped<SignInManager<AppUser>>();
            services.AddScoped<RoleManager<IdentityRole>>();

            services.AddTransient<ITokenManager, TokenManager>();
            services.AddScoped<IResponseGeneratorService, ResponseGeneratorService>();
            services.AddScoped<IAdminService, AdminService>();
            services.AddScoped<IEmailSenderService, EmailSenderService>();
            services.AddScoped<ITokenService, TokenService>();
            services.AddScoped<IAdminRepository, AdminRepository>();


            // Register AutoMapper and add the mapping profile
            var mappingConfig = new MapperConfiguration(mc =>
            {
                mc.AddProfile(new RegisterMappingConfiguration());
                // Add other profiles if needed
            });

            IMapper mapper = mappingConfig.CreateMapper();
            services.AddSingleton(mapper);

            //Setup External services

            return services;
        }
    }
}
