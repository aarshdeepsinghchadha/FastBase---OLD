using Application.Admin;
using Application.Common;
using Application.Interface.Core;
using Application.Interface.Repository;
using Application.Interface.Token;
using Infrastructure.Services.Admin;
using Microsoft.AspNetCore.Http;
using Moq;

namespace NUnitTest
{
    /// <summary>
    /// Unit tests for the <see cref="AdminService"/> class.
    /// </summary>
    public class AdminServiceUnitTestCase
    {
        private Mock<IAdminRepository> _adminRepositoryMock;
        private Mock<IResponseGeneratorService> _responseGeneratorServiceMock;
        private AdminService _adminService;
        private Mock<ITokenService> _tokenServiceMock;

        /// <summary>
        /// Sets up the necessary mocks and initializes the <see cref="AdminService"/> instance for testing.
        /// </summary>
        [SetUp]
        public void Setup()
        {
            _adminRepositoryMock = new Mock<IAdminRepository>();
            _responseGeneratorServiceMock = new Mock<IResponseGeneratorService>();
            _tokenServiceMock = new Mock<ITokenService>();
            _adminService = new AdminService(_tokenServiceMock.Object, _adminRepositoryMock.Object, _responseGeneratorServiceMock.Object);
        }

        /// <summary>
        /// Tests the behavior of <see cref="AdminService.RegisterUserServiceAsync"/> when the password and confirm password mismatch.
        /// </summary>
        [Test]
        public async Task RegisterUserServiceAsync_PasswordMismatch_ReturnsBadRequest()
        {
            // Arrange
            var registerDto = new RegisterDto { Password = "password", ConfirmPassword = "mismatch" };
            var origin = "http://example.com";

            // Set up the response generator service
            var expectedResponse = new ReturnResponse
            {
                Status = false, // Set to the expected success value
                StatusCode = StatusCodes.Status400BadRequest, // Set to the expected status code
                Message = "Password and confirm password do not match.", // Set to the expected message
                                                                         // Add other properties as needed based on your ReturnResponse class
            };

            _responseGeneratorServiceMock.Setup(x => x.GenerateResponseAsync(false, StatusCodes.Status400BadRequest, "Password and confirm password do not match."))
                                         .ReturnsAsync(expectedResponse);

            // Act
            var result = await _adminService.RegisterUserServiceAsync(registerDto, origin);

            // Assert
            Assert.That(result, Is.EqualTo(expectedResponse));
        }

        /// <summary>
        /// Tests the behavior of <see cref="AdminService.RegisterUserServiceAsync"/> when the password and confirm password match.
        /// </summary>
        [Test]
        public async Task RegisterUserServiceAsync_PasswordMatch_CallsRepositoryAndReturnsResult()
        {
            // Arrange
            var registerDto = new RegisterDto { Password = "password", ConfirmPassword = "password" };
            var origin = "http://example.com";
            var expectedRepositoryResponse = new ReturnResponse(/* expected response parameters */);

            // Set up the response generator service
            _responseGeneratorServiceMock.Setup(x => x.GenerateResponseAsync(true, StatusCodes.Status200OK, "Registration successful."))
                                         .ReturnsAsync(new ReturnResponse(/* expected response parameters */));

            _adminRepositoryMock.Setup(x => x.RegisterUserAsync(It.IsAny<RegisterDto>(), It.IsAny<string>()))
                                .ReturnsAsync(expectedRepositoryResponse);

            // Act
            var result = await _adminService.RegisterUserServiceAsync(registerDto, origin);

            // Assert
            Assert.That(result, Is.EqualTo(expectedRepositoryResponse));

            // Verify that _adminRepository.RegisterUserAsync was called with the correct parameters
            _adminRepositoryMock.Verify(x => x.RegisterUserAsync(registerDto, origin), Times.Once);
        }
    }

}
