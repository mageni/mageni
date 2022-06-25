###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_bof_vuln01_feb14_win.nasl 34938 2014-02-03 18:02:51Z Feb$
#
# Oracle MySQL Client Remote Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804082");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-0001");
  script_bugtraq_id(65298);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-03 18:02:51 +0530 (Mon, 03 Feb 2014)");
  script_name("Oracle MySQL Client Remote Buffer Overflow Vulnerability (Windows)");


  script_tag(name:"summary", value:"This host is installed with Oracle MySQL Client and is prone to remote buffer
overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an user-supplied input is not properly validated when handling
server versions in client/mysql.cc.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate certain data and
cause a DoS (Denial of Service).");
  script_tag(name:"affected", value:"Oracle MySQL version 5.5.34 and earlier.");
  script_tag(name:"solution", value:"Upgrade to MySQL version 5.5.35 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.scip.ch/en/?vuldb.12135");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1029708");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"http://www.mysql.com");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");
include("host_details.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if("MySQL Server" >< appName)
  {
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insloc) continue;

    clientVer = fetch_file_version(sysPath: insloc, file_name:"bin\mysql.exe");

    if(clientVer && clientVer =~ "^(5\.5)")
    {
      if(version_in_range(version:clientVer, test_version:"5.5", test_version2:"5.5.34"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
