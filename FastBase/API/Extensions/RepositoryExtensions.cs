using Domain;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Persistance;
using System.Data;

namespace API.Extensions
{
    /// <summary> 
    /// Extensions for repositories 
    /// </summary> 

    public static class RepositoryExtensions
    {
        /// <summary> 
        /// Add repostories to the service collection 
        /// </summary> 
        /// <param name="services">Service collection</param> 
        /// <param name="config">Configuration</param> 
        /// <returns>Service collection</returns> 

        public static IServiceCollection AddRepositories(this IServiceCollection services, IConfiguration config)
        {
            var enableDataLogging = config.GetValue<bool>("Logging:EnableEFCoreLogging");
            var rentReminderBuilder = new DbContextOptionsBuilder<DataContext>();
            #region postgres
            services
                .AddScoped<IDbConnection>(p => new NpgsqlConnection(config.GetConnectionString("FastBaseDb")));
            #endregion
            #region postgres
            var rentReminderOptions = rentReminderBuilder
                .UseNpgsql(config.GetConnectionString("FastBaseDb"), providerOptions => providerOptions.EnableRetryOnFailure())
                .EnableSensitiveDataLogging(enableDataLogging)
                .Options;
            #endregion

            #region sql
            //var rentReminderOptions = rentReminderBuilder
            //  .UseSqlServer(config.GetConnectionString("FastBaseSQLDb"), providerOptions => providerOptions.EnableRetryOnFailure())
            //  .EnableSensitiveDataLogging(enableDataLogging)
            //  .Options;
            #endregion

            var rentReminderNoRetryBuilder = new DbContextOptionsBuilder<DataContext>();

            #region postgres
            var rentReminderNoRetryOptions = rentReminderNoRetryBuilder
                .UseNpgsql(config.GetConnectionString("FastBaseDb"))
                .EnableSensitiveDataLogging(enableDataLogging)
                .Options;
            #endregion

            #region sql
            //var rentReminderNoRetryOptions = rentReminderNoRetryBuilder
            //                .UseSqlServer(config.GetConnectionString("FastBaseSQLDb"))
            //                .EnableSensitiveDataLogging(enableDataLogging)
            //                .Options;
            #endregion
            // Setup repositories 
            services.AddScoped<DataContext>(_ => new DataContext(rentReminderOptions));

           
            return services;
        }
    }
}
