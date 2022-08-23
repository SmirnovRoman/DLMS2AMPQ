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

using Gurux.DLMS.Objects;
using Gurux.DLMS.Enums;

namespace Gurux.DLMS
{
    /// <summary>
    /// Access item is used to generate Access Service message.
    /// </summary>
    public class GXDLMSAccessItem
    {
        /// <summary>
        /// COSEM target object.
        /// </summary>
        public GXDLMSObject Target
        {
            get;
            set;
        }


        /// <summary>
        /// Executed command type.
        /// </summary>
        public AccessServiceCommandType Command
        {
            get;
            set;
        }

        /// <summary>
        /// Attribute index.
        /// </summary>
        public byte Index
        {
            get;
            set;
        }

        /// <summary>
        /// Reply error code.
        /// </summary>
        public ErrorCode Error
        {
            get;
            set;
        }

        /// <summary>
        /// Reply value.
        /// </summary>
        public object Value
        {
            get;
            set;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GXDLMSAccessItem()
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="command">Command to execute.</param>
        /// <param name="target">COSEM target object.</param>
        /// <param name="index"> Attribute index.</param>
        public GXDLMSAccessItem(AccessServiceCommandType command, GXDLMSObject target, byte index)
        {
            Command = command;
            Target = target;
            Index = index;
        }
    }
}
