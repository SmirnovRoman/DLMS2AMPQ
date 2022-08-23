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

using Gurux.DLMS.Enums;
using System;

namespace Gurux.DLMS.Objects
{
    public class GXxDLMSContextType
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public GXxDLMSContextType()
        {
            DlmsVersionNumber = 6;
        }

        /// <summary>
        /// Conformance
        /// </summary>
        public Conformance Conformance
        {
            get;
            set;
        }
        public UInt16 MaxReceivePduSize
        {
            get;
            set;
        }
        public UInt16 MaxSendPduSize
        {
            get;
            set;
        }

        /// <summary>
        /// Dlms Version Number.
        /// </summary>
        public Byte DlmsVersionNumber
        {
            get;
            set;
        }

        public sbyte QualityOfService
        {
            get;
            set;
        }
        public byte[] CypheringInfo
        {
            get;
            set;
        }


        public override string ToString()
        {
            return Conformance + " " + MaxReceivePduSize.ToString() + " " + MaxSendPduSize.ToString()
                 + " " + DlmsVersionNumber.ToString() + " " + QualityOfService.ToString() + " " +
                 Internal.GXCommon.ToHex(CypheringInfo, true);
        }
    };
}
