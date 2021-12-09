#if NETSTANDARD || NET5_0_OR_GREATER
using System;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace SimpleImpersonation
{
    /// <summary>
    /// Provides ability to run code within the context of a specific user.
    /// </summary>
    public static class ImpersonationAsync
    {
        /// <summary>
        /// Impersonates a specific user account to perform the specified function.
        /// </summary>
        /// <param name="credentials">The credentials of the user account to impersonate.</param>
        /// <param name="logonType">The logon type used when impersonating the user account.</param>
        /// <param name="function">The function to perform.</param>
        public static Task RunAsUserAsync(UserCredentials credentials, LogonType logonType, Func<Task> function)
        {
            using (var tokenHandle = credentials.Impersonate(logonType))
            {
                return RunImpersonatedAsync(tokenHandle, _ => function());
            }
        }

        /// <summary>
        /// Impersonates a specific user account to perform the specified function.
        /// </summary>
        /// <param name="credentials">The credentials of the user account to impersonate.</param>
        /// <param name="logonType">The logon type used when impersonating the user account.</param>
        /// <param name="logonProvider">The logon provider used when impersonating the user account.</param>
        /// <param name="function">The function to perform.</param>
        public static Task RunAsUserAsync(UserCredentials credentials, LogonType logonType, LogonProvider logonProvider, Func<Task> function)
        {
            using (var tokenHandle = credentials.Impersonate(logonType, logonProvider))
            {
                return RunImpersonatedAsync(tokenHandle, _ => function());
            }
        }

        /// <summary>
        /// Impersonates a specific user account to perform the specified function.
        /// </summary>
        /// <param name="credentials">The credentials of the user account to impersonate.</param>
        /// <param name="logonType">The logon type used when impersonating the user account.</param>
        /// <param name="function">The function to perform, which accepts a <see cref="SafeAccessTokenHandle"/> to the user account as its only parameter.</param>
        public static Task RunAsUserAsync(UserCredentials credentials, LogonType logonType, Func<SafeAccessTokenHandle, Task> function)
        {
            using (var tokenHandle = credentials.Impersonate(logonType))
            {
                return RunImpersonatedAsync(tokenHandle, function);
            }
        }

        /// <summary>
        /// Impersonates a specific user account to perform the specified function.
        /// </summary>
        /// <param name="credentials">The credentials of the user account to impersonate.</param>
        /// <param name="logonType">The logon type used when impersonating the user account.</param>
        /// <param name="logonProvider">The logon provider used when impersonating the user account.</param>
        /// <param name="function">The function to perform, which accepts a <see cref="SafeAccessTokenHandle"/> to the user account as its only parameter.</param>
        public static Task RunAsUserAsync(UserCredentials credentials, LogonType logonType, LogonProvider logonProvider, Func<SafeAccessTokenHandle, Task> function)
        {
            using (var tokenHandle = credentials.Impersonate(logonType, logonProvider))
            {
                return RunImpersonatedAsync(tokenHandle, function);
            }
        }

        /// <summary>
        /// Impersonates a specific user account to execute the specified function.
        /// </summary>
        /// <typeparam name="T">The return type of the function.</typeparam>
        /// <param name="credentials">The credentials of the user account to impersonate.</param>
        /// <param name="logonType">The logon type used when impersonating the user account.</param>
        /// <param name="function">The function to execute, which accepts a <see cref="SafeAccessTokenHandle"/> to the user account as its only parameter.</param>
        /// <returns>The result of executing the function.</returns>
        public static Task<T> RunAsUser<T>(UserCredentials credentials, LogonType logonType, Func<Task<T>> function)
        {
            using (var tokenHandle = credentials.Impersonate(logonType))
            {
                return RunImpersonatedAsync(tokenHandle, _ => function());
            }
        }

        /// <summary>
        /// Impersonates a specific user account to execute the specified function.
        /// </summary>
        /// <typeparam name="T">The return type of the function.</typeparam>
        /// <param name="credentials">The credentials of the user account to impersonate.</param>
        /// <param name="logonType">The logon type used when impersonating the user account.</param>
        /// <param name="logonProvider">The logon provider used when impersonating the user account.</param>
        /// <param name="function">The function to execute, which accepts a <see cref="SafeAccessTokenHandle"/> to the user account as its only parameter.</param>
        /// <returns>The result of executing the function.</returns>
        public static Task<T> RunAsUser<T>(UserCredentials credentials, LogonType logonType, LogonProvider logonProvider, Func<Task<T>> function)
        {
            using (var tokenHandle = credentials.Impersonate(logonType, logonProvider))
            {
                return RunImpersonatedAsync(tokenHandle, _ => function());
            }
        }

        /// <summary>
        /// Impersonates a specific user account to execute the specified function.
        /// </summary>
        /// <typeparam name="T">The return type of the function.</typeparam>
        /// <param name="credentials">The credentials of the user account to impersonate.</param>
        /// <param name="logonType">The logon type used when impersonating the user account.</param>
        /// <param name="function">The function to execute.</param>
        /// <returns>The result of executing the function.</returns>
        public static Task<T> RunAsUser<T>(UserCredentials credentials, LogonType logonType, Func<SafeAccessTokenHandle, Task<T>> function)
        {
            using (var tokenHandle = credentials.Impersonate(logonType))
            {
                return RunImpersonatedAsync(tokenHandle, function);
            }
        }

        /// <summary>
        /// Impersonates a specific user account to execute the specified function.
        /// </summary>
        /// <typeparam name="T">The return type of the function.</typeparam>
        /// <param name="credentials">The credentials of the user account to impersonate.</param>
        /// <param name="logonType">The logon type used when impersonating the user account.</param>
        /// <param name="logonProvider">The logon provider used when impersonating the user account.</param>
        /// <param name="function">The function to execute.</param>
        /// <returns>The result of executing the function.</returns>
        public static Task<T> RunAsUser<T>(UserCredentials credentials, LogonType logonType, LogonProvider logonProvider, Func<SafeAccessTokenHandle, Task<T>> function)
        {
            using (var tokenHandle = credentials.Impersonate(logonType, logonProvider))
            {
                return RunImpersonatedAsync(tokenHandle, function);
            }
        }
        
        private static Task<T> RunImpersonatedAsync<T>(SafeAccessTokenHandle tokenHandle, Func<SafeAccessTokenHandle, Task<T>> function)
        {
            return WindowsIdentity.RunImpersonatedAsync<T>(tokenHandle, () => function(tokenHandle));

        }
        private static Task RunImpersonatedAsync(SafeAccessTokenHandle tokenHandle, Func<SafeAccessTokenHandle, Task> function)
        {
            return WindowsIdentity.RunImpersonatedAsync(tokenHandle, () => function(tokenHandle));
        }
    }
}
#endif
