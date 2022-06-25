##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_synology_photo_station_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Synology Photo Station Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:synology:synology_photo_station';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140298");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-15 13:49:40 +0700 (Tue, 15 Aug 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-11151", "CVE-2017-11152", "CVE-2017-11153", "CVE-2017-11154", "CVE-2017-11155");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Photo Station Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_synology_photo_station_detect.nasl");
  script_mandatory_keys("synology_photo_station/installed", "synology_photo_station/psv");

  script_tag(name:"summary", value:"Synology Photo Station is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Synology Photo Station is prone to multiple vulnerabilities:

  - A vulnerability in synotheme_upload.php in Synology Photo Station allows remote attackers to upload arbitrary
files without authentication via the logo_upload action. (CVE-2017-11151)

  - Directory traversal vulnerability in PixlrEditorHandler.php in Synology Photo Station allows remote attackers
to write arbitrary files via the path parameter. (CVE-2017-11152)

  - Deserialization vulnerability in synophoto_csPhotoMisc.php in Synology Photo Station allows remote attackers to
gain administrator privileges via a crafted serialized payload. (CVE-2017-11153)

  - Unrestricted file upload vulnerability in PixlrEditorHandler.php in Synology Photo Station allows remote
attackers to create arbitrary PHP scripts via the type parameter. (CVE-2017-11154)

  - An information exposure vulnerability in index.php in Synology Photo Station allows remote attackers to obtain
sensitive system information via unspecified vectors. (CVE-2017-11155)");

  script_tag(name:"affected", value:"Synology Photo Station before 6.7.3-3432 and 6.3-2967");

  script_tag(name:"solution", value:"Update to version 6.7.3-3432, 6.3-2967 (for DSM 5.2 users) or later.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3356");
  script_xref(name:"URL", value:"https://www.synology.com/en-global/support/security/Synology_SA_17_34_PhotoStation");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

psv = get_kb_item("synology_photo_station/psv");
if (!psv)
  exit(0);

if (psv == "6") {
  if (version_is_less(version: version, test_version: "6.7.3-3432")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.7.3-3432");
    security_message(port: port, data: report);
    exit(0);
  }
}
else {
  if (version_is_less(version: version, test_version: "6.3-2967")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.3-2967");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
