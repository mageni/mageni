###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_synology_sa_18_15.nasl 14156 2019-03-13 14:38:13Z cfischer $
#
# Synology Photo Station Multiple Vulnerabilities (Synology_SA_18_15)
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

CPE = "cpe:/a:synology:synology_photo_station";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112305");
  script_version("$Revision: 14156 $");
  script_cve_id("CVE-2018-8925", "CVE-2018-8926");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 15:38:13 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-06-13 14:14:05 +0200 (Wed, 13 Jun 2018)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology Photo Station Multiple Vulnerabilities (Synology_SA_18_15)");

  script_tag(name:"summary", value:"Multiple vulnerabilities allow remote attackers to hijack the authentication
  of administrators or to conduct privilege escalation attacks via a susceptible version of Photo Station.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is running on the target host.");

  script_tag(name:"insight", value:"- Cross-site request forgery (CSRF) vulnerability in admin/user.php in Synology Photo Station
  allows remote attackers to hijack the authentication of administrators via the (1) username, (2) password, (3) admin, (4) action, (5) uid, or (6) modify_admin parameter.

  - Permissive regular expression vulnerability in synophoto_dsm_user in Synology Photo Station allows remote authenticated users
  to conduct privilege escalation attacks via the fullname parameter.");

  script_tag(name:"affected", value:"Synology Photo Station before 6.8.5-3471 and before 6.3-2975.");

  script_tag(name:"solution", value:"Upgrade to Synology Photo Station version 6.8.5-3471 or 6.3-2975 respectively.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/support/security/Synology_SA_18_15");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_synology_photo_station_detect.nasl");
  script_mandatory_keys("synology_photo_station/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE)) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
ver = infos['version'];
path = infos['location'];

if(ver =~ "^6\.3") {
  if(version_is_less(version:ver, test_version:"6.3-2975")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"6.3-2975", install_path:path);
    security_message(port:port, data:report);
    exit(0);
  }
}

if(ver =~ "^6\.8") {
  if(version_is_less(version:ver, test_version:"6.8.5-3471")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"6.8.5-3471", install_path:path);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
