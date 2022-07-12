###############################################################################
# OpenVAS Vulnerability Test
#
# Description: Microsoft 'hxvz.dll' ActiveX Control Memory Corruption Vulnerability (948881)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801491");
  script_version("2019-05-03T12:31:27+0000");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-10 14:22:58 +0100 (Mon, 10 Jan 2011)");
  script_bugtraq_id(28606);
  script_cve_id("CVE-2008-1086");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft 'hxvz.dll' ActiveX Control Memory Corruption Vulnerability (948881)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/29714");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/41464");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Apr/1019800.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS10-023.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers execute arbitrary code.");
  script_tag(name:"affected", value:"Microsoft Windows 2K  Service Pack 4 and prior

  Microsoft Windows XP  Service Pack 2 and prior

  Microsoft Windows 2K3 Service Pack 2 and prior

  Microsoft Windows Vista Service Pack 1 and prior

  Microsoft Windows Server 2008 Service Pack 1/2 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an error in 'hxvz.dll' ActiveX control.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-023.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  Workaround:

  Set the killbit for the following CLSIDs,
  {314111b8-a502-11d2-bbca-00c04f8ec294}, {314111c6-a502-11d2-bbca-00c04f8ec294}");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

## MS08-023 Hotfix check
if(hotfix_missing(name:"948881") == 0){
  exit(0);
}

## CLSID List
clsids = make_list(
  "{314111b8-a502-11d2-bbca-00c04f8ec294}",
  "{314111c6-a502-11d2-bbca-00c04f8ec294}"
 );

foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
