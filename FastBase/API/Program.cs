using API.Extensions;
using Domain.Admin;
using Infrastructure.Middleware;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Persistance;
using Swashbuckle.AspNetCore.SwaggerUI;
using System.Reflection;


var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDistributedMemoryCache();
builder.Services.AddTransient<TokenManagerMiddleware>();
builder.Services.AddTransient<Seed>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddRepositories(builder.Configuration);
builder.Services.AddService(builder.Configuration);
builder.Services.AddAuthenticaionService(builder.Configuration);


// Add Swagger services
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "My API", Version = "v1" });

    // Add a security definition for the API key
    options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.ApiKey,
        Name = "Authorization",
        In = ParameterLocation.Header,
        Description = "API key needed to access the endpoints"
    });

    // Add a security requirement to all endpoints
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "ApiKey"
                }
            },
            new string[] {}
        }
    });

    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    options.IncludeXmlComments(xmlPath);

});


var app = builder.Build();
app.UseRouting();
app.UseDefaultFiles();
app.UseCors(builder => builder
                    .AllowAnyOrigin()
                    //.WithOrigins("http://127.0.0.1:8080")
                    .AllowAnyHeader()
                    .AllowAnyMethod());
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

using var scope = app.Services.CreateScope();
var services = scope.ServiceProvider;
var context = services.GetRequiredService<DataContext>();
var userManager = services.GetRequiredService<UserManager<AppUser>>();
var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
await context.Database.MigrateAsync();
await Seed.SeedData(context, userManager, roleManager);

app.UseSwagger();
// Enable Swagger UI
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
    options.DocExpansion(DocExpansion.None);
});

app.Run();
