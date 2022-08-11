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
  script_oid("1.3.6.1.4.1.25623.1.0.118263");
  script_version("2021-11-02T11:09:34+0000");
  script_tag(name:"last_modification", value:"2021-11-02 11:09:34 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-01 11:45:13 +0100 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_cve_id("CVE-2011-1521");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python Multiple Vulnerabilities (May 2011) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to an error in handling 'ftp://' and 'file://' URL
  schemes in the Python urllib and urllib2 extensible libraries processing the urllib open URL request.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to access sensitive
  information or cause a denial of service of a Python web application, processing URLs, via a
  specially crafted urllib open URL request.");

  script_tag(name:"affected", value:"Python version 2.x before 2.7.2 and 3.x before 3.2.1");

  script_tag(name:"solution", value:"Update to version 2.7.2, 3.2.1 or later.");

  script_xref(name:"URL", value:"http://bugs.python.org/issue11662");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=690560");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/03/24/5");

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

if( version_in_range( version:version, test_version:"2.0", test_version2:"2.7.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.0", test_version2:"3.2.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.2.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
