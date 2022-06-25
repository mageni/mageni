###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_flex_sdk_swf_files_xss_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Adobe Flex SDK 'SWF' Files Cross-Site Scripting Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902765");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-2461");
  script_bugtraq_id(50869);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-13 00:49:37 +0530 (Tue, 13 Dec 2011)");
  script_name("Adobe Flex SDK 'SWF' Files Cross-Site Scripting Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47053/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50869/info");
  script_xref(name:"URL", value:"http://kb2.adobe.com/cps/915/cpsid_91544.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-25.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an
  affected site.");
  script_tag(name:"affected", value:"Adobe Flex SDK version 3.x through 3.6 and 4.x through 4.5.1");
  script_tag(name:"insight", value:"The flaw is due to certain unspecified input passed to SWF files developed
  using the framework is not properly sanitised before being returned to the
  user.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flex SDK and is prone to
  cross site scripting vulnerability.");
  script_tag(name:"solution", value:"Apply the patch  *****
  NOTE: Ignore this warning if patch is applied already.
  *****

  ****************************************************************
  Note: This script detects Adobe Flex SDK installed as part of Adobe
  Flex Builder only. If SDK is installed separately, manual verification
  is required.
  ****************************************************************");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://kb2.adobe.com/cps/915/cpsid_91544.html");
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
  flexName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Adobe Flex" >< flexName)
  {
    sdkPath = registry_get_sz(key:key + item, item:"FrameworkPath");

    if("sdk" >< sdkPath)
    {
      sdkVer = eregmatch(pattern:"\\([0-9.]+)", string:sdkPath);
      if(!isnull(sdkVer[1]))
      {
        if(version_in_range(version:sdkVer[1], test_version:"3.0", test_version2:"3.6") ||
           version_in_range(version:sdkVer[1], test_version:"4.0", test_version2:"4.5.1"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);

        }
      }
    }
  }
}
