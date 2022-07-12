###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_activex_control_mult_vuln_may13.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Microsoft Windows ActiveX Control Multiple Vulnerabilities (2820197)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803701");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-05-21 13:06:04 +0530 (Tue, 21 May 2013)");
  script_name("Microsoft Windows ActiveX Control Multiple Vulnerabilities (2820197)");
  script_cve_id("CVE-2013-0108");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2820197");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/advisory/2820197");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers execute arbitrary code,
  and can compromise a vulnerable system.");

  script_tag(name:"affected", value:"Microsoft Windows 8

  Microsoft Windows Server 2012

  Microsoft Windows XP x32 Edition Service Pack 3 and prior

  Microsoft Windows XP x64 Edition Service Pack 2 and prior

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaws are due to errors in the handling of Honeywell Enterprise Buildings
  Integrator, SymmetrE and ComfortPoint Open Manager ActiveX controls.");

  script_tag(name:"summary", value:"This script will list all the vulnerable activex controls installed
  on the remote windows machine with references and cause.");

  script_tag(name:"solution", value:"Apply the patch  Workaround:
  Set the killbit for the following CLSIDs,

  {0d080d7d-28d2-4f86-bfa1-d582e5ce4867},

  {29e9b436-dfac-42f9-b209-bd37bafe9317}.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2820197");
  exit(0);
}

include("smb_nt.inc");
include("secpod_activex.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

clsids = make_list("{0d080d7d-28d2-4f86-bfa1-d582e5ce4867}",
                   "{29e9b436-dfac-42f9-b209-bd37bafe9317}");

foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
