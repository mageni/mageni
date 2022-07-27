###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_wddm_unspecified_vuln_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Oracle VM VirtualBox Graphics Driver(WDDM) Unspecified Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804433");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-2441");
  script_bugtraq_id(66868);
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-18 12:39:26 +0530 (Fri, 18 Apr 2014)");
  script_name("Oracle VM VirtualBox Graphics Driver(WDDM) Unspecified Vulnerability (Windows)");


  script_tag(name:"summary", value:"This host is installed with Oracle VM VirtualBox and is prone to unspecified
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is  due to an error within the Graphics driver(WDDM) for Windows
guests component and can be exploited by disclose, update, insert, or delete
certain data and to cause a crash.");
  script_tag(name:"impact", value:"Successful exploitation will allow local users to disclose sensitive
information, manipulate certain data, and cause a DoS (Denial of
Service).");
  script_tag(name:"affected", value:"Oracle Virtualization VirtualBox 4.1.x before 4.1.32, 4.2.x before 4.2.24,
and 4.3.x before 4.3.10 on Windows");
  script_tag(name:"solution", value:"Upgrade to Oracle VM VirtualBox version 4.1.32, 4.2.24, 4.3.10 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57937");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  script_xref(name:"URL", value:"https://www.virtualbox.org");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^(4\.(1|2|3))")
{
  if(version_in_range(version:virtualVer, test_version:"4.2.0", test_version2:"4.2.23")||
     version_in_range(version:virtualVer, test_version:"4.3.0", test_version2:"4.3.9") ||
     version_in_range(version:virtualVer, test_version:"4.1.0", test_version2:"4.1.31"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
