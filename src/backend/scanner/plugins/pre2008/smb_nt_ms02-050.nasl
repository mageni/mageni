###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-050.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Certificate Validation Flaw Could Enable Identity Spoofing (Q328145)
#
# Authors:
# Michael Scheidell SECNAP Network Security
#
# Copyright:
# Copyright (C) 2002 SECNAP Network Security, LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11145");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5410);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-1183", "CVE-2002-0862");
  script_name("Certificate Validation Flaw Could Enable Identity Spoofing (Q328145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 SECNAP Network Security, LLC");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"Hotfix to fix Certificate Validation Flaw (Q329115)
  is not installed.

  The vulnerability could enable an attacker who had a valid end-entity certificate to issue a
  subordinate certificate that, although bogus, would nevertheless pass validation. Because
  CryptoAPI is used by a wide range of applications, this could enable a variety of identity
  spoofing attacks.");

  script_tag(name:"impact", value:"Identity spoofing.");

  script_tag(name:"affected", value:"Microsoft Windows 98

  Microsoft Windows 98 Second Edition

  Microsoft Windows Me

  Microsoft Windows NT 4.0

  Microsoft Windows NT 4.0, Terminal Server Edition

  Microsoft Windows 2000

  Microsoft Windows XP

  Microsoft Office for Mac

  Microsoft Internet Explorer for Mac

  Microsoft Outlook Express for Mac");

  script_tag(name:"solution", value:"The vendor has released updates, please see the references for more information.");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms02-050.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q329115") > 0  )
  security_message(port:0);
 