# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-052.nasl 12746 2018-12-10 15:26:37Z cfischer $
# Description: Flaw in Microsoft VM Could Allow Code Execution (810030)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11177");
  script_version("$Revision: 12746 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 16:26:37 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6371, 6372);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2002-1257", "CVE-2002-1258", "CVE-2002-1183", "CVE-2002-0862");
  script_name("Flaw in Microsoft VM Could Allow Code Execution (810030)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 SECNAP Network Security, LLC");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"Hotfix to fix Flaw in Microsoft VM
  could Allow Code Execution (810030)");

  script_tag(name:"impact", value:"Three vulnerabilities, the most
  serious of which could enable an attacker to gain complete
  control over a user's system.");

  script_tag(name:"affected", value:"Versions of the Microsoft virtual machine (Microsoft VM) are
  identified by build numbers, which can be determined using the JVIEW tool as discussed in the FAQ.
  All builds of the Microsoft VM up to and including build 5.0.3805 are affected by these
  vulnerabilities.");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms02-052.mspx");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms02-069.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has releases updates, please see the references for more information.");

  exit(0);
}

include("secpod_reg.inc");
include("host_details.inc");

if ( hotfix_check_sp(xp:2, win2k:4) <= 0 ) exit(0);

version = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{08B0E5C0-4FCB-11CF-AAA5-00401C608500}/Version");
if (!version) exit(0);

# should be "5,00,3807,0";
v = split(version, sep:",", keep:FALSE);
if ( int(v[0]) < 5 ||
     ( int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) < 3809) )
{
 if ( hotfix_missing(name:"810030") > 0 )
   security_message(port:0);
}
