using Domain.Admin;
using Domain.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.ChangeTracking.Internal;

namespace Persistance
{
    public class Seed
    {
        public static async Task SeedData(DataContext context, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {

            #region Roles

            await SeedRolesAsync(roleManager);

            #endregion

            #region for multiple user
            //var users = new List<AppUser>
            //{
            //    new AppUser
            //    {
            //        FirstName = "Aarshdeep",
            //        LastName = "Chadha",
            //        UserName = "Aarshdeep.Chadha",
            //        Email = "aarshdeep.chadha@indianic.com",
            //        EmailConfirmed = true,
            //        PhoneNumber = "4282342140",
            //        Role = "Administrator"
            //    }
            //};
            #endregion

            var sysAdmin = new AppUser
            {
                FirstName = "Aarshdeep",
                LastName = "Chadha",
                UserName = "Aarshdeep.Chadha",
                Email = "aarshdeep.chadha@indianic.com",
                EmailConfirmed = true,
                PhoneNumber = "4282342140",
                Role = "Administrator"
            };

            if (!userManager.Users.Any())
            {
                #region for multiple user
                //foreach (var user in users)
                //{
                //    await userManager.CreateAsync(user, "Pa$$w0rd");
                //}
                #endregion
                await userManager.CreateAsync(sysAdmin, "Pa$$w0rd");

                await userManager.AddToRoleAsync(sysAdmin, SystemEnums.Roles.SystemAdmin.ToString());

                await context.SaveChangesAsync();
            }
        }
        private static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            if (!await roleManager.RoleExistsAsync(SystemEnums.Roles.SystemAdmin.ToString()))
            {
                await roleManager.CreateAsync(new IdentityRole(SystemEnums.Roles.SystemAdmin.ToString()));
            }

            if (!await roleManager.RoleExistsAsync(SystemEnums.Roles.User.ToString()))
            {
                await roleManager.CreateAsync(new IdentityRole(SystemEnums.Roles.User.ToString()));
            }
        }
    }
}
