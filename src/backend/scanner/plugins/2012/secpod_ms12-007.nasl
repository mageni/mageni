###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-007.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# Microsoft AntiXSS Library Information Disclosure Vulnerability (2607664)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902785");
  script_version("$Revision: 11855 $");
  script_cve_id("CVE-2012-0007");
  script_bugtraq_id(51291);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"creation_date", value:"2012-01-11 13:30:24 +0530 (Wed, 11 Jan 2012)");
  script_name("Microsoft AntiXSS Library Information Disclosure Vulnerability (2607664)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47516/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026499");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-007");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass the filter and
  conduct cross-site scripting attacks. Successful exploits may allow attackers
  to execute arbitrary script code and steal cookie-based authentication
  credentials.");
  script_tag(name:"affected", value:"Microsoft Anti-Cross Site Scripting Library version 3.x
  Microsoft Anti-Cross Site Scripting Library version 4.0");
  script_tag(name:"insight", value:"The flaw is due to error in library which fails to properly filter
  HTML code from user-supplied input. A remote user may be able to exploit a
  target application that uses the library to cause arbitrary scripting code to
  be executed by the target user's browser.");
  script_tag(name:"solution", value:"Upgrade to Microsoft Anti-Cross Site Scripting Library version 4.2.1");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-007.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  xssName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Microsoft AntiXSS" >< xssName ||
     "Microsoft Anti-Cross Site Scripting Library" >< xssName)
  {
    xssVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(xssVer)
    {
      if(xssVer =~ "^3\.*" ||
         version_in_range(version:xssVer, test_version:"4.0", test_version2:"4.2.0"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
