###############################################################################
# OpenVAS Vulnerability Test
#
# ownCloud XSS and CSRF Protection Bypass Vulnerabilities Mar18 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813054");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2014-1665");
  script_bugtraq_id(65457);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-23 12:50:26 +0530 (Fri, 23 Mar 2018)");
  script_name("ownCloud XSS and CSRF Protection Bypass Vulnerabilities Mar18 (Linux)");

  script_tag(name:"summary", value:"This host is running ownCloud and is prone
  to XSS and CSRF vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an insufficient
  validation of user supplied input for the 'filename' while uploading file.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attackers to conduct a XSS attack when the victim tries to either view the
  contents of the file or delete the file. If the victim is an ownCloud
  administrator, an attacker can force the mounting of the webserver's local
  file system, leading to unauthorized access to server resources and potentially
  shell access.");

  script_tag(name:"affected", value:"ownCloud version 6.0.0a on Linux.");

  script_tag(name:"solution", value:"Upgrade to ownCloud 6.0.1 or later.
  If upgrading is not an option, then the file can be removed by either
  1) manually removing the file from the disk via command line interface, or
  2) first renaming the file to something else and then deleting the file.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/31427");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/125086");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/installed", "Host/runs_unixoide");
  script_xref(name:"URL", value:"https://owncloud.org");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!owport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:owport, exit_no_version:TRUE)) exit(0);
owVer = infos['version'];
path = infos['location'];

if(owVer == "6.0.0a")
{
  report = report_fixed_ver(installed_version:owVer, fixed_version: "6.0.1 or later", install_path:path);
  security_message(port:owport, data:report);
  exit(0);
}
exit(0);
