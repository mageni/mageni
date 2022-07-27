###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Server Privilege Elevation Vulnerabilities (2780176)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902953");
  script_version("2019-05-03T12:31:27+0000");
  script_bugtraq_id(58372, 58370, 58367, 58371);
  script_cve_id("CVE-2013-0080", "CVE-2013-0083", "CVE-2013-0084", "CVE-2013-0085");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-03-13 11:50:53 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft SharePoint Server Privilege Elevation Vulnerabilities (2780176)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52551");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687418");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553407");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028278");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-024");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server_or_Foundation_or_Services/Installed");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to bypass certain security
  restrictions, disclose certain system data and conduct cross-site scripting
  and spoofing attacks.");
  script_tag(name:"affected", value:"Microsoft SharePoint Server 2010 Service Pack 1
  Microsoft SharePoint Foundation 2010 Service Pack 1");
  script_tag(name:"insight", value:"- The application allows users to perform certain actions via HTTP requests
    without performing proper validity checks to verify the requests.

  - Certain unspecified input is not properly sanitized before being returned
    to the user.

  - An error related to the W3WP process when handling URLs can be exploited
    to cause a buffer overflow and subsequently terminate the W3WP process via
    a specially crafted URL.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-024.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-0-24");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## SharePoint Server 2007 and 2010
CPE = "cpe:/a:microsoft:sharepoint_server";
if(version = get_app_version(cpe:CPE))
{
  ## SharePoint Server 2010 (wosrv)
  if(version =~ "^14\..*")
  {
    ## Not getting updated any file
    # # so checking  for hotfix
    if(hotfix_missing(name:"2553407") == 1)
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

## SharePoint Foundation 2010
CPE = "cpe:/a:microsoft:sharepoint_foundation";
if(version = get_app_version(cpe:CPE))
{
  key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0";
  if(registry_key_exists(key:key))
  {
    dllPath = registry_get_sz(key:key, item:"Location");
    if(dllPath)
    {
      dllVer  = fetch_file_version(sysPath:dllPath, file_name:"BIN\Onetutil.dll");
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6134.5000")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
