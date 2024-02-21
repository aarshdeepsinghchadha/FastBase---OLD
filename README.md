# FastBase API
- # Overview:

- FastBase API is a .NET Core Web API project incorporating various technologies and best practices for efficient development. It leverages features such as Code-First Database, Entity Framework, AutoMapper, Swagger Documentation, LINQ, ASP.NET Core Identity, and more. The project follows Clean Architecture and Repository Pattern, ensuring a structured and maintainable codebase.

- # Key Features:

1. **Authentication and Authorization**: The project implements role-based authentication using ASP.NET Core Identity. The middleware includes role mechanisms to control access to resources.


2. **Email Services**: Integrated SendGrid and MailGun for email services, providing flexibility in choosing email providers. The IEmailSenderService interface includes methods for sending emails using SendGrid and MailGun.

3. **Response Generator**: The IResponseGeneratorService interface facilitates the generation of generic responses, enhancing code consistency and clarity.

4. **NUnit Testing**: Demonstrates NUnit testing with Setup, Arrange, Act, Assert methodology, focusing on testing the service layer rather than the repository layer.

5. **Database Connection Options**: The project supports both PostgreSQL and SQL Server. Developers can choose their preferred database by following simple setup instructions.

6. **Token Management Middleware**: The TokenManagerMiddleware ensures the validity of JWT tokens before allowing access to protected resources. It works in conjunction with the TokenManager class, which manages token-related functionalities.

7. **Extensions**: Three extension classes—AddAuthenticaionService, RepositoryExtensions, and ServiceExtensions—simplify and modularize various aspects of the project.

8. **Pre-written Code for Database Setup**: Includes pre-written code snippets within the #region for connecting to PostgreSQL and SQL Server databases.

- # Usage:

- **Clone the project to the desired folder.**
- **Choose the preferred database (PostgreSQL or SQL Server) and follow the provided instructions.**
- **Configure email services (SendGrid or MailGun) by reading the respective documentation.**
- **Explore and use the provided Postman collection for testing the APIs.**


- # Future Enhancements: 

- Implementation of OAuth.
- Integration of Redis with an example.

**Note: Suggestions are always welcome! Enjoy coding! 😊**
