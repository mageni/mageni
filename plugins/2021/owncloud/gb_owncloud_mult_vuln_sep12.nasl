# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146730");
  script_version("2021-09-22T07:17:45+0000");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-21 08:37:55 +0000 (Tue, 21 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-4389", "CVE-2012-4390", "CVE-2012-4391", "CVE-2012-4392");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 4.0.7 Multiple Vulnerabilities (oC-SA-2012-012, oC-SA-2012-013, oC-SA-2012-014, oC-SA-2012-015");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2012-4389: Incomplete blacklist in lib/migrate.php allows remote attackers to execute
  arbitrary code by uploading a crafted .htaccess file in an import.zip file and accessing an
  uploaded PHP file.

  - CVE-2012-4390: apps/calendar/appinfo/remote.php and apps/contacts/appinfo/remote.php allows
  remote authenticated users to enumerate the registered users via unspecified vectors.

  - CVE-2012-4391: Cross-site request forgery (CSRF) in core/ajax/appconfig.php allows remote
  attackers to hijack the authentication of administrators for requests that edit the app
  configurations.

  - CVE-2012-4392: index.php does not properly validate the oc_token cookie, which allows remote
  attackers to bypass authentication via a crafted oc_token cookie value.");

  script_tag(name:"affected", value:"ownCloud prior to version 4.0.7.");

  script_tag(name:"solution", value:"Update to version 4.0.7 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2012/09/02/2");
  script_xref(name:"URL", value:"https://github.com/owncloud/security-advisories/blob/master/server/oc-sa-2012-012.json");
  script_xref(name:"URL", value:"https://github.com/owncloud/security-advisories/blob/master/server/oc-sa-2012-013.json");
  script_xref(name:"URL", value:"https://github.com/owncloud/security-advisories/blob/master/server/oc-sa-2012-014.json");
  script_xref(name:"URL", value:"https://github.com/owncloud/security-advisories/blob/master/server/oc-sa-2012-015.json");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);