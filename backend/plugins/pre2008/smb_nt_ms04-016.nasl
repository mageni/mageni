###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_nt_ms04-016.nasl 12603 2018-11-30 14:57:24Z cfischer $
#
# Vulnerability in DirectPlay Could Allow Denial of Service (839643)
#
# Authors:
# Noam Rathaus noamr@beyondsecurity.com
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.12267");
  script_version("$Revision: 12603 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:57:24 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10487);
  script_cve_id("CVE-2004-0202");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Vulnerability in DirectPlay Could Allow Denial of Service (839643)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"A denial of service vulnerability exists in the implementation of the
  IDirectPlay4 application programming interface (API) of Microsoft DirectPlay because of a lack of robust
  packet validation.");

  script_tag(name:"impact", value:"If a user is running a networked DirectPlay application,
  an attacker who successfully exploited this vulnerability could cause the DirectPlay application to fail.
  The user would have to restart the application to resume functionality.");

  script_tag(name:"solution", value:"The vendor has released updates, please see the references for more information.");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms04-016.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

dvers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version");
if ( !dvers ) exit(0);

vers = get_kb_item("SMB/WindowsVersion");
if ( !vers ) exit(0);

if ( vers == "5.0" )
{
  if (  ( dvers != "4.08.00.0400" ) &&
	( dvers != "4.08.00.0400" ) &&
	( dvers != "4.08.01.0881" ) &&
	( dvers != "4.08.01.0901" ) &&
	( dvers != "4.08.02.0134" ) &&
	( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) &&
	( dvers != "4.09.00.0902" ) )
	exit (0);
}


if ( vers == "5.1" )
{
  if (  ( dvers != "4.08.02.0134" ) &&
	( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) &&
	( dvers != "4.09.00.0902" ) )
	exit (0);
}


if ( vers == "5.2" )
{
  if (  ( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) &&
	( dvers != "4.09.00.0902" ) )
	exit (0);
}

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB839643") > 0 &&
     hotfix_missing(name:"KB839643-DirectX8") > 0 &&
     hotfix_missing(name:"KB839643-DirectX81") > 0 &&
     hotfix_missing(name:"KB839643-DirectX82") > 0 &&
     hotfix_missing(name:"KB839643-DirectX9")  > 0 )
  security_message(port:0);
