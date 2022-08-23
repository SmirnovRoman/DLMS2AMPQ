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

namespace Gurux.DLMS.Objects.Italy
{
    /// <summary>
    /// Plan descriptor.
    /// </summary>
    public class GXBandDescriptor
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public GXBandDescriptor()
        {
            WorkingDayIntervals = new GXDLMSInterval[5];
            SaturdayIntervals = new GXDLMSInterval[5];
            HolidayIntervals = new GXDLMSInterval[5];
            for (int pos = 0; pos != 5; ++pos)
            {
                WorkingDayIntervals[pos] = new GXDLMSInterval();
                SaturdayIntervals[pos] = new GXDLMSInterval();
                HolidayIntervals[pos] = new GXDLMSInterval();
            }
        }
        /// <summary>
        /// Day of month when the season will become active.
        /// </summary>
        [XmlIgnore()]
        public byte DayOfMonth
        {
            get;
            set;
        }
        /// <summary>
        /// Month of the year when the season will become active.
        /// </summary>
        [XmlIgnore()]
        public byte Month
        {
            get;
            set;
        }

        /// <summary>
        /// Working day intervals.
        /// </summary>
        [XmlIgnore()]
        public GXDLMSInterval[] WorkingDayIntervals
        {
            get;
            set;
        }

        /// <summary>
        /// Saturday intervals.
        /// </summary>
        [XmlIgnore()]
        public GXDLMSInterval[] SaturdayIntervals
        {
            get;
            set;
        }

        /// <summary>
        /// Saturday intervals.
        /// </summary>
        [XmlIgnore()]
        public GXDLMSInterval[] HolidayIntervals
        {
            get;
            set;
        }
    }
}
