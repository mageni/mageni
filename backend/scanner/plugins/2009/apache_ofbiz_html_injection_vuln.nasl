# Copyright (C) 2009 Christian Eric Edjenguele
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

CPE = "cpe:/a:apache:ofbiz";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101020");
  script_version("2021-12-21T05:20:49+0000");
  script_tag(name:"last_modification", value:"2021-12-21 05:20:49 +0000 (Tue, 21 Dec 2021)");
  script_tag(name:"creation_date", value:"2009-04-22 20:27:36 +0200 (Wed, 22 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2006-6589", "CVE-2006-6587");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache OFBiz <= 3.0.0 Multiple HTML Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Web application abuses");
  script_dependencies("apache_ofbiz_http_detect.nasl");
  script_mandatory_keys("apache/ofbiz/detected");

  script_tag(name:"summary", value:"Apache OFBiz is prone to multiple HTML injection
  vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2006-6589: Search_String parameter HTML injection

  - CVE-2006-6587: Unspecified HTML injection");

  script_tag(name:"solution", value:"Download the latest release form Apache Software Foundation
  (OFBiz) website.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! ver = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:ver, test_version:"3.0.0" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"Unknown" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
