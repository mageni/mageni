###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_hid_over_usb_code_exec_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# MS Windows HID Functionality (Over USB) Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801581");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)");
  script_cve_id("CVE-2011-0638");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("MS Windows HID Functionality (Over USB) Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://www.cs.gmu.edu/~astavrou/publications.html");
  script_xref(name:"URL", value:"http://news.cnet.com/8301-27080_3-20028919-245.html");
  script_xref(name:"URL", value:"http://www.blackhat.com/html/bh-dc-11/bh-dc-11-briefings.html#Stavrou");

  script_tag(name:"impact", value:"Successful exploitation will allows user-assisted attackers to
  execute arbitrary programs via crafted USB data.");

  script_tag(name:"affected", value:"All Microsoft Windows systems with an enabled USB device driver
  and no local protection mechanism against the automatic enabling of additional Human Interface
  Device (HID).");

  script_tag(name:"insight", value:"The flaw is due to error in USB device driver (hidserv.dll),
  which does not properly warn the user before enabling additional Human Interface Device (HID)
  functionality.");

  script_tag(name:"solution", value:"No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  A workaround is to introduce device filtering on the target host to only allow trusted
  USB devices to be enabled automatically. Once this workaround is in place an Overwrite
  for this vulnerability can be created to mark it as a false positive.");

  script_tag(name:"summary", value:"This host is installed with a USB device driver software and is
  prone to a code execution vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

sysPath = smb_get_systemroot();
if( ! sysPath ) exit( 0 );

dllPath = sysPath + "\system32\hidserv.dll";
share   = ereg_replace( pattern:"([A-Z]):.*", replace:"\1$", string:dllPath );
file    = ereg_replace( pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath );
dllVer  = GetVer( file:file, share:share );

if( dllVer ) {
  security_message( port:0, data:"File checked for existence: " + dllPath );
}

exit( 99 );
