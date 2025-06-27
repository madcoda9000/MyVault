using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MyVault.Server.Services
{
    /// <summary>
    /// class for encryption service
    /// </summary>
    public interface IEncryptionServices
    {
        #region Methods
        
            /// <summary>
            /// method decrypt string
            /// </summary>
            /// <param name="text"></param>
            /// <returns></returns>
            string DecryptString(string text);
            /// <summary>
            /// method encrypt string
            /// </summary>
            /// <param name="text"></param>
            /// <returns></returns>
            string EncryptString(string text);
            /// <summary>
            /// method isencrypted
            /// </summary>
            /// <param name="text"></param>
            /// <returns></returns>
            bool IsEncrypted(string text);
    
        #endregion
    }
}