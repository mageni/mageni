###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sunway_force_control_webserver_bof_vuln.nasl 12010 2018-10-22 08:23:57Z mmartin $
#
# Sunway ForceControl WebServer 'httpsvr.exe' Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802156");
  script_version("$Revision: 12010 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:23:57 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-13 07:51:43 +0200 (Tue, 13 Sep 2011)");
  script_cve_id("CVE-2011-2960");
  script_bugtraq_id(48328);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Sunway ForceControl WebServer 'httpsvr.exe' Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45033");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17721/");
  script_xref(name:"URL", value:"http://www.cnvd.org.cn/vulnerability/CNVD-2011-05347");
  script_xref(name:"URL", value:"http://www.sunwayland.com.cn/news_info_.asp?Nid=3593");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-11-167-01.pdf");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to an error in the WebServer component
(httpsvr.exe) and can be exploited to cause a heap-based buffer overflow via
a specially crafted URL sent in a web request.");
  script_tag(name:"solution", value:"Vendor has released a patch to fix the issue, please refer
below link for patch information.");
  script_xref(name:"URL", value:"http://www.sunwayland.com.cn/news_info_.asp?Nid=3593");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Sunway ForceControl and is prone to
buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
denial of service or execute arbitrary code.");
  script_tag(name:"affected", value:"Sunway ForceControl 6.1 SP1, SP2, and SP3.");
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
  sunName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Forcecontrol" >< sunName)
  {
    sunVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if("6.1" >< sunVer)
    {
      exePath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!isnull(exePath))
      {
        httpVer = fetch_file_version(sysPath:exePath, file_name:"httpsvr.exe");
        if(httpVer != NULL)
        {
          if(version_is_less_equal(version:httpVer, test_version:"6.0.5.3")){
            security_message( port: 0, data: "The target host was found to be vulnerable" ) ;
          }
        }
      }
    }
  }
}
