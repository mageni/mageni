###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nextcloud_server_mult_vuln_oct18_lin.nasl 13338 2019-01-29 07:44:39Z mmartin $
#
# Nextcloud Server < 14.0.0 Multiple Vulnerabilities (NC-SA-2018-011, NC-SA-2018-012, NC-SA-2018-014) (Linux)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112412");
  script_version("$Revision: 13338 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-29 08:44:39 +0100 (Tue, 29 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-11-01 11:49:50 +0100 (Thu, 01 Nov 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-16464", "CVE-2018-16465", "CVE-2018-16467");

  script_name("Nextcloud Server < 14.0.0 Multiple Vulnerabilities (NC-SA-2018-011, NC-SA-2018-012, NC-SA-2018-014) (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"This host is running Nextcloud Server
  and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Missing state would not enforce the use of a second factor at login if the the provider of the second factor failed to load. (CVE-2018-16464)

  - A missing access check could lead to continued access to password protected link shares when the owner had changed the password. (CVE-2018-16465)

  - A missing check could give unauthorized access to the previews of single file password protected shares. (CVE-2018-16467)");
  script_tag(name:"affected", value:"Nextcloud Server before version 14.0.0.");
  script_tag(name:"solution", value:"Upgrade Nextcloud Server to version 14.0.0 or later.");

  script_xref(name:"URL", value:"https://hackerone.com/reports/146133");
  script_xref(name:"URL", value:"https://hackerone.com/reports/317711");
  script_xref(name:"URL", value:"https://hackerone.com/reports/231917");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2018-011");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2018-012");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2018-014");

  exit(0);
}

CPE = "cpe:/a:nextcloud:nextcloud";

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"14.0.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"14.0.0", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
