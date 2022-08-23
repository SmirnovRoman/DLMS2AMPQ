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

using System.Xml.Serialization;

namespace Gurux.DLMS.Enums
{
    /// <summary>
    /// Used DLMS standard.
    /// </summary>
    public enum Standard
    {
        /// <summary>
        /// Meter uses default DLMS IEC 62056 standard. https://dlms.com
        /// </summary>
        [XmlEnum("0")]
        DLMS = 0,
        /// <summary>
        /// Meter uses India DLMS standard IS 15959-2. https://www.standardsbis.in
        /// </summary>
        [XmlEnum("1")]
        India,
        /// <summary>
        /// Meter uses Italy DLMS standard UNI/TS 11291-11-2. https://uni.com
        /// </summary>
        [XmlEnum("2")]
        Italy,
        /// <summary>
        /// Meter uses Saudi Arabia DLMS standard.
        /// </summary>
        [XmlEnum("3")]
        SaudiArabia,
        /// <summary>
        /// Meter uses IDIS DLMS standard. https://www.idis-association.com/
        /// </summary>
        [XmlEnum("4")]
        Idis,
        /// <summary>
        /// Meter uses Spain DLMS standard.
        /// </summary>
        [XmlEnum("5")]
        Spain,
    }
}
