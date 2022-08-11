###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_media_services_actvx_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Microsoft Windows Media Services nskey.dll ActiveX BOF Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.800310");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5232");
  script_bugtraq_id(30814);
  script_name("Microsoft Windows Media Services nskey.dll ActiveX BOF Vulnerability");

  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/30814.html.txt");
  script_xref(name:"URL", value:"http://www.microsoft.com/windows/windowsmedia/forpros/server/server.aspx");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code, and cause the
  victim's browser to crash.");

  script_tag(name:"affected", value:"Microsoft Windows Media Services on Windows NT/2000 Server.");

  script_tag(name:"insight", value:"The flaw is due to an error in CallHTMLHelp method in nskey.dll file,
  which fails to perform adequate boundary checks on user-supplied input.");

  script_tag(name:"summary", value:"This host is installed with Windows Media Services and is prone to
  Buffer Overflow vulnerability.");

  script_tag(name:"solution", value:"Vendor has released a patch to fix this issue. Windows Media
  Services customers should contact the vendor for support for upgrade or patch.

  Workaround: Set a kill bit for the CLSID
  {2646205B-878C-11D1-B07C-0000C040BCDB}");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

wmsPath = registry_get_sz(key:"SYSTEM\ControlSet001\Services\nsmonitor",
                          item:"ImagePath");
if(!wmsPath){
  exit(0);
}

wmsPath = wmsPath - "nspmon.exe" + "nskey.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wmsPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:wmsPath);

wmsVer = GetVer(file:file, share:share);
if(wmsVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:wmsVer, test_version:"4.1.00.3917"))
{
  clsid = "{2646205B-878C-11D1-B07C-0000C040BCDB}";
  regKey = "SOFTWARE\Classes\CLSID\" + clsid;
  if(registry_key_exists(key:regKey))
  {
    activeKey = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid;
    killBit = registry_get_dword(key:activeKey, item:"Compatibility Flags");
    if(killBit && (int(killBit) == 1024)){
      exit(0);
    }
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
