#if NETSTANDARD || NET5_0_OR_GREATER
using System;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Xunit;

namespace SimpleImpersonation.UnitTests
{
    // NOTE: Unit tests for this project must be executed as an administrator,
    //       because they create a temporary user for testing successful impersonation.

    public class ImpersonationAsyncTests : IClassFixture<UserPrincipalFixture>
    {
        private readonly UserPrincipalFixture _fixture;

        public ImpersonationAsyncTests(UserPrincipalFixture fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public async Task ImpersonateAsync_RunAsUser_PlainPassword_Function()
        {
            var userNameBefore = WindowsIdentity.GetCurrent().Name;

            var credentials = new UserCredentials(_fixture.Username, _fixture.Password);

            var userNameDuring = await ImpersonationAsync.RunAsUserAsync(credentials, LogonType.Interactive,
                () => Task.FromResult(WindowsIdentity.GetCurrent().Name));

            var userNameAfter = WindowsIdentity.GetCurrent().Name;

            Assert.Equal(userNameBefore, userNameAfter);
            Assert.Equal(_fixture.FullUsername, userNameDuring);
        }

        [Fact]
        public async Task ImpersonateAsync_RunAsUser_PlainPassword_FunctionWithTokenHandle()
        {
            var userNameBefore = WindowsIdentity.GetCurrent().Name;

            var credentials = new UserCredentials(_fixture.Username, _fixture.Password);

            var (userNameDuring, tokenIsValid) = await ImpersonationAsync.RunAsUserAsync(credentials, LogonType.Interactive,
                tokenHandle => Task.FromResult((WindowsIdentity.GetCurrent().Name, !tokenHandle.IsInvalid)));

            var userNameAfter = WindowsIdentity.GetCurrent().Name;

            Assert.Equal(userNameBefore, userNameAfter);
            Assert.Equal(_fixture.FullUsername, userNameDuring);
            Assert.True(tokenIsValid);
        }

      [Fact]
        public async Task ImpersonateAsync_RunAsUser_SecurePassword_Function()
        {
            var userNameBefore = WindowsIdentity.GetCurrent().Name;

            var credentials = new UserCredentials(_fixture.Username, _fixture.PasswordAsSecureString);

            var userNameDuring = await ImpersonationAsync.RunAsUserAsync(credentials, LogonType.Interactive,
                () => Task.FromResult(WindowsIdentity.GetCurrent().Name));

            var userNameAfter = WindowsIdentity.GetCurrent().Name;

            Assert.Equal(userNameBefore, userNameAfter);
            Assert.Equal(_fixture.FullUsername, userNameDuring);
        }

        [Fact]
        public async Task ImpersonateAsync_RunAsUser_SecurePassword_FunctionWithTokenHandle()
        {
            var userNameBefore = WindowsIdentity.GetCurrent().Name;

            var credentials = new UserCredentials(_fixture.Username, _fixture.PasswordAsSecureString);

            var (userNameDuring, tokenIsValid) = await ImpersonationAsync.RunAsUserAsync(credentials, LogonType.Interactive,
                tokenHandle => Task.FromResult((WindowsIdentity.GetCurrent().Name, !tokenHandle.IsInvalid)));

            var userNameAfter = WindowsIdentity.GetCurrent().Name;

            Assert.Equal(userNameBefore, userNameAfter);
            Assert.Equal(_fixture.FullUsername, userNameDuring);
            Assert.True(tokenIsValid);
        }
    }
}
#endif