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

using System;

namespace Gurux.DLMS.Enums
{
    /// <summary>
    /// Enumerates all comformance bits.
    /// </summary>
    /// <remarks>
    /// More information:<br/>
    /// https://www.gurux.fi/Gurux.DLMS.Conformance
    /// </remarks>
    [Flags]
    public enum Conformance : uint
    {
        /// <summary>
        /// Conformance is not used.
        /// </summary>
        None = 0,
        /// <summary>
        /// Reserved zero conformance bit.
        /// </summary>
        ReservedZero = 0x1,
        /// <summary>
        /// General protection conformance bit.
        /// </summary>
        GeneralProtection = 0x2,
        /// <summary>
        /// General block transfer conformance bit.
        /// </summary>
        GeneralBlockTransfer = 0x4,
        /// <summary>
        /// Read conformance bit.
        /// </summary>
        Read = 0x8,
        /// <summary>
        /// Write conformance bit.
        /// </summary>
        Write = 0x10,
        /// <summary>
        /// Un confirmed write conformance bit.
        /// </summary>
        UnconfirmedWrite = 0x20,
        /// <summary>
        /// Delta value encoding.
        /// </summary>
        DeltaValueEncoding = 0x40,
        /// <summary>
        /// Reserved seven conformance bit.
        /// </summary>
        ReservedSeven = 0x80,
        /// <summary>
        /// Attribute 0 supported with set conformance bit.
        /// </summary>
        Attribute0SupportedWithSet = 0x100,
        /// <summary>
        /// Priority mgmt supported conformance bit.
        /// </summary>
        PriorityMgmtSupported = 0x200,
        /// <summary>
        /// Attribute 0 supported with get conformance bit.
        /// </summary>
        Attribute0SupportedWithGet = 0x400,
        /// <summary>
        /// Block transfer with get or read conformance bit.
        /// </summary>
        BlockTransferWithGetOrRead = 0x800,
        /// <summary>
        /// Block transfer with set or write conformance bit.
        /// </summary>
        BlockTransferWithSetOrWrite = 0x1000,
        /// <summary>
        /// Block transfer with action conformance bit.
        /// </summary>
        BlockTransferWithAction = 0x2000,
        /// <summary>
        /// multiple references conformance bit.
        /// </summary>
        MultipleReferences = 0x4000,
        /// <summary>
        /// Information report conformance bit.
        /// </summary>
        InformationReport = 0x8000,
        /// <summary>
        /// Data notification conformance bit.
        /// </summary>
        DataNotification = 0x10000,
        /// <summary>
        /// Access conformance bit.
        /// </summary>
        Access = 0x20000,
        /// <summary>
        /// Parameterized access conformance bit.
        /// </summary>
        ParameterizedAccess = 0x40000,
        /// <summary>
        /// Get conformance bit.
        /// </summary>
        Get = 0x80000,
        /// <summary>
        /// Set conformance bit.
        /// </summary>
        Set = 0x100000,
        /// <summary>
        /// Selective access conformance bit.
        /// </summary>
        SelectiveAccess = 0x200000,
        /// <summary>
        /// Event notification conformance bit.
        /// </summary>
        EventNotification = 0x400000,
        /// <summary>
        /// Action conformance bit.
        /// </summary>
        Action = 0x800000,
    }
}