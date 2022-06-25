###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winlog_lite_bof_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Sielco Sistemi Winlog PRO Buffer overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802552");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-4037");
  script_bugtraq_id(50932);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-03 18:03:49 +0530 (Tue, 03 Jan 2012)");
  script_name("Sielco Sistemi Winlog PRO Buffer overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47078");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1026388");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-11-298-01.pdf");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error when processing certain values
  in project files and can be exploited to cause a buffer overflow by tricking
  a user into loading a malicious project file.");
  script_tag(name:"solution", value:"Upgrade to  Winlog Lite version 2.07.09 or later.");
  script_tag(name:"summary", value:"This host is installed with Sielco Sistemi Winlog PRO and is prone
  to buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application.");
  script_tag(name:"affected", value:"Winlog Lite version before 2.07.09");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.sielcosistemi.com/en/download/public/index.html");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Sielco Sistemi\Winlog Lite")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Winlog Lite";

if(!registry_key_exists(key:key)){
  exit(0);
}

winName = registry_get_sz(key:key, item:"DisplayName");

if("Winlog Lite" >< winName)
{
  winVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(winVer!= NULL)
  {
    if(version_is_less(version:winVer, test_version:"2.07.09")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

exit(99);
