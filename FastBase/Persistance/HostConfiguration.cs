using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Persistance
{
    public class HostConfiguration
    {
        public IConfiguration Configuration { get; set; }
        public ILoggerFactory LoggerFactory { get; set; }

        public HostConfiguration(IConfiguration configuration, ILoggerFactory loggerFactory)
        {
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            LoggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        }

        public static HostConfiguration Build(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables()
                .AddCommandLine(args)
                .Build();

            var loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(
                builder =>
                {
                    var logConfiguration = configuration.GetSection("Logging");
                    builder.AddConfiguration(configuration);
                    builder.AddSimpleConsole(
                        consoleConfig =>
                        {
                            consoleConfig.IncludeScopes = true;
                            consoleConfig.SingleLine = false;
                            consoleConfig.TimestampFormat = "yyyy-MM-dd HH:mm:ss";
                            consoleConfig.UseUtcTimestamp = true;
                        });
                });
            var hostConfiguration = new HostConfiguration(configuration, loggerFactory);
            return hostConfiguration;
        }
    }
}
