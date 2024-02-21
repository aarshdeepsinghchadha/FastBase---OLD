using Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Persistance
{
    public class DataContextFactory : IDesignTimeDbContextFactory<DataContext>
    {
        public DataContext CreateDbContext(string[] args)
        {
            var hostConfiguration = HostConfiguration.Build(args);
            var connectionString = hostConfiguration.Configuration.GetConnectionString("FastBaseDb");
            var optionsBuilder = new DbContextOptionsBuilder<DataContext>();

            bool logSqlStatements = hostConfiguration.Configuration.GetValue<bool>("LogSqlStatements");
            if (logSqlStatements)
            {
                optionsBuilder.UseLoggerFactory(hostConfiguration.LoggerFactory);
            }
            #region postgres
            optionsBuilder.UseNpgsql(connectionString, contextBuilder =>
            {
                contextBuilder.MigrationsAssembly(System.Reflection.Assembly.GetExecutingAssembly().FullName);
            });
            #endregion

            #region sql
            //optionsBuilder.UseSqlServer(connectionString, contextBuilder =>
            //{
            //    contextBuilder.MigrationsAssembly(System.Reflection.Assembly.GetExecutingAssembly().FullName);
            //});
            #endregion
            var dbContext = new DataContext(optionsBuilder.Options);
            return dbContext;
        }
    }
}
