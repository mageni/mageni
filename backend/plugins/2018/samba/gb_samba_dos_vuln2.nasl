##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_dos_vuln2.nasl 13517 2019-02-07 07:51:12Z mmartin $
#
# Samba DoS Vulnerability (CVE-2018-16841)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:samba:samba";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141734");
  script_version("$Revision: 13517 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-07 08:51:12 +0100 (Thu, 07 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-29 10:37:40 +0700 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2018-16841");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba DoS Vulnerability (CVE-2018-16841)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"A user with a valid certificate or smart card can crash the Samba AD DC's
KDC.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Samba 4.3.0 and later.");

  script_tag(name:"solution", value:"Update to version 4.7.12, 4.8.7, 4.9.3 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2018-16841.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path    = infos['location'];

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.7.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.12", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.8.0", test_version2: "4.8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.7", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.9.0", test_version2: "4.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
