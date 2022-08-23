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
using Gurux.DLMS.Enums;

namespace Gurux.DLMS.Objects
{
    public interface IGXDLMSBase
    {
        /// <summary>
        /// Returns collection of attributes to read.
        /// </summary>
        /// <remarks>
        /// If attribute is static and already read or device is returned HW error it is not returned.
        /// </remarks>
        /// <param name="all">All items are returned even if they are read already.</param>
        /// <returns>Collection of attributes to read.</returns>
        int[] GetAttributeIndexToRead(bool all);

        /// <summary>
        /// Returns amount of attributes.
        /// </summary>
        /// <returns>Count of attributes.</returns>
        int GetAttributeCount();

        /// <summary>
        /// Returns amount of methods.
        /// </summary>
        /// <returns></returns>
        int GetMethodCount();

        /// <summary>
        /// Returns data type of selected attribute index.
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        DataType GetDataType(int index);

        /// <summary>
        /// Returns names of attribute indexes.
        /// </summary>
        /// <returns></returns>
        string[] GetNames();

        /// <summary>
        /// Returns names of method indexes.
        /// </summary>
        string[] GetMethodNames();

        /// <summary>
        /// Returns value of given attribute.
        /// </summary>
        /// <remarks>
        /// When raw parameter us not used example register multiplies value by scalar.
        /// </remarks>
        /// <param name="settings">DLMS settings.</param>
        /// <param name="e">Get parameters.</param>
        /// <returns>Value of the attribute index.</returns>
        Object GetValue(GXDLMSSettings settings, ValueEventArgs e);

        /// <summary>
        /// Set value of given attribute.
        /// </summary>
        /// <remarks>
        /// When raw parameter us not used example register multiplies value by scalar.
        /// </remarks>
        /// <param name="settings">DLMS settings.</param>
        /// <param name="e">Set parameters.</param>
        void SetValue(GXDLMSSettings settings, ValueEventArgs e);

        /// <summary>
        /// Invokes method.
        /// </summary>
        /// <param name="settings">DLMS settings.</param>
        /// <param name="e">Invoke parameters.</param>
        byte[] Invoke(GXDLMSSettings settings, ValueEventArgs e);

        /// <summary>
        /// Load object content from XML.
        /// </summary>
        /// <param name="reader">XML reader.</param>
        void Load(GXXmlReader reader);

        /// <summary>
        /// Save object content to XML.
        /// </summary>
        /// <param name="writer">XML writer.</param>
        void Save(GXXmlWriter writer);

        /// <summary>
        /// Handle actions after Load.
        /// </summary>
        /// <param name="reader">XML reader.</param>
        void PostLoad(GXXmlReader reader);

        /// <summary>
        /// Returns maximum supported version.
        /// </summary>
        /// <returns></returns>
        int GetMaxSupportedVersion();
    }
}
