###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intel_amt_clickjack_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Intel Active Management Technology Clickjacking Vulnerability
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

CPE = "cpe:/h:intel:active_management_technology";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106877");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-16 13:48:56 +0700 (Fri, 16 Jun 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-5697");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology Clickjacking Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_intel_amt_webui_detect.nasl");
  script_mandatory_keys("intel_amt/installed");

  script_tag(name:"summary", value:"Insufficient clickjacking protection in the Web User Interface of Intel AMT
firmware potentially allows a remote attacker to hijack users web clicks via attacker's crafted web page.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Intel AMT firmware versions before 9.1.40.1000, 9.5.60.1952, 10.0.50.1004,
11.0.0.1205, and 11.6.25.1129.");

  script_tag(name:"solution", value:"Update firmware to version 9.1.40.1000, 9.5.60.1952, 10.0.50.1004,
11.0.0.1205, 11.6.25.1129 or later.");

  script_xref(name:"URL", value:"https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00081&languageid=en-fr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

# test for the full version even we just get the major version (e.g. 9.1.40)
if (version_is_less(version: version, test_version: "9.1.40.1000")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.40.1000");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^9\.5\.") {
  if (version_is_less(version: version, test_version: "9.5.60.1952")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.5.60.1952");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^10\.0\.") {
  if (version_is_less(version: version, test_version: "10.0.50.1004")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "10.0.50.1004");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^11\.6\.") {
  if (version_is_less(version: version, test_version: "11.6.25.1129")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "11.6.25.1129");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
