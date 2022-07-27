##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nextcloud_mult_vuln_win1.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Nextcloud Multiple Vulnerabilities (Windows)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106702");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-30 14:13:45 +0700 (Thu, 30 Mar 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-9463", "CVE-2016-9467", "CVE-2016-9468");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Nextcloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nextcloud is prone to multiple vulnerabilities:

  - SMB user Authentication bypass (CVE-2016-9463)

  - Content spoofing in the files app (CVE-2016-9467)

  - Content spoofing in the dav app (CVE-2016-9468)");

  script_tag(name:"affected", value:"Nextcloud Server prior to 9.0.54 and prior to 10.0.1");

  script_tag(name:"solution", value:"Update 9.0.54, 10.0.1 or later versions.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=nc-sa-2016-006");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=nc-sa-2016-010");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "9.0.54")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.54");
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "10.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
