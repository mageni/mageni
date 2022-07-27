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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112998");
  script_version("2021-11-02T11:44:13+0000");
  script_tag(name:"last_modification", value:"2021-11-02 11:44:13 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-02 10:32:11 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-4238");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python 2.6.x < 2.6.9, 2.7.x < 2.7.6, 3.2.x < 3.2.6, 3.3.x < 3.3.3 SSL NULL Byte Vulnerability (bpo-18709) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python's SSL module fails to handle NULL bytes inside subjectAltNames general names.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The ssl.match_hostname function in the SSL module in Python
  does not properly handle a '0' character in a domain name in the Subject Alternative Name field
  of an X.509 certificate, which allows man-in-the-middle attackers to spoof arbitrary SSL servers
  via a crafted certificate issued by a legitimate Certification Authority.");

  script_tag(name:"affected", value:"Python 2.6 before 2.6.9, 2.7 before 2.7.6, 3.2 before 3.2.6 and 3.3 before 3.3.3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/ssl-null-subjectaltnames.html");
  script_xref(name:"Advisory-ID", value:"bpo-18709");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version:version, test_version:"2.6", test_version2:"2.6.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.6.9", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"2.7", test_version2:"2.7.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.2", test_version2:"3.2.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.2.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.3", test_version2:"3.3.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.3.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}


exit( 99 );
