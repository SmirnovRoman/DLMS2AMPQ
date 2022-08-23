//
// --------------------------------------------------------------------------
//  Gurux Ltd
//
//
//
// Filename:        $HeadURL$
//
// Version:         $Revision$,
//                  $Date$
//                  $Author$
//
// Copyright (c) Gurux Ltd
//
//---------------------------------------------------------------------------
//
//  DESCRIPTION
//
// This file is a part of Gurux Device Framework.
//
// Gurux Device Framework is Open Source software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2 of the License.
// Gurux Device Framework is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// More information of Gurux products: https://www.gurux.org
//
// This code is licensed under the GNU General Public License v2.
// Full text may be retrieved at http://www.gnu.org/licenses/gpl-2.0.txt
//---------------------------------------------------------------------------

using Gurux.DLMS.ASN;
using Gurux.DLMS.Objects.Enums;
using System.Collections.Generic;

namespace Gurux.DLMS.Objects
{
    /// <summary>
    /// Certificate info.
    /// </summary>
    public class GXDLMSCertificateCollection : List<GXDLMSCertificateInfo>
    {
        /// <summary>
        /// Find certificate with given parameters.
        /// </summary>
        /// <param name="entity">Certificate entity.</param>
        /// <param name="type">Certificate type.</param>
        /// <param name="systemtitle">System title.</param>
        /// <returns></returns>
        public GXDLMSCertificateInfo Find(CertificateEntity entity, CertificateType type, byte[] systemtitle)
        {
            string subject = GXAsn1Converter.SystemTitleToSubject(systemtitle);
            foreach (GXDLMSCertificateInfo it in this)
            {
                if ((it.Entity == CertificateEntity.Server && entity == CertificateEntity.Server) ||
                    (it.Entity == CertificateEntity.Client && entity == CertificateEntity.Client)
                    && it.Subject == subject)
                {
                    return it;
                }
            }
            return null;
        }
    }
}
