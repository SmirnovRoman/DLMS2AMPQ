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

namespace Gurux.DLMS.Objects.Enums
{
    /// <summary>
    /// Enumerates communication port protection status values.
    /// </summary>
    public enum ProtectionStatus
    {
        /// <summary>
        /// Port is unlocked.
        /// </summary>
        Unlocked = 0,
        /// <summary>
        /// The port is temporarily locked. Communication is not possible.
        /// </summary>
        TemporarilyLocked = 1,
        /// <summary>
        /// Port is locked. Communication is not possible.
        /// </summary>
        Locked = 2,
    }
}
