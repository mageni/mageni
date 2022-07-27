###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_7z_nd_mew_packer_parsing_dos_vuln_lin.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# ClamAV Crafted '7z' And 'Mew Packer' Parsing Denial of Service Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807376");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-1372", "CVE-2016-1371");
  script_bugtraq_id(93221, 93222);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-13 13:09:56 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ClamAV Crafted '7z' And 'Mew Packer' Parsing Denial of Service Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"This host is installed with ClamAV and is
  prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in parsing the crafted 7z files, which causes attacker to  crash the
    application.

  - An error in parsing crafted mew packer, which causes attacker to  crash the
    application.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to crash the application.");

  script_tag(name:"affected", value:"ClamAV versions before 0.99.2 on Linux");

  script_tag(name:"solution", value:"Upgrade to ClamAV version 0.99.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://blog.clamav.net/2016/05/clamav-0992-has-been-released.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ClamAV/remote/Ver", "Host/runs_unixoide");
  script_require_ports(3310);
  script_xref(name:"URL", value:"http://www.clamav.net");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!clamPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!clamVer = get_app_version(cpe:CPE, port:clamPort)){
  exit(0);
}

if(version_is_less(version:clamVer, test_version:"0.99.2"))
{
  report = report_fixed_ver(installed_version:clamVer, fixed_version:"0.99.2");
  security_message(data:report, port:clamPort);
  exit(0);
}
