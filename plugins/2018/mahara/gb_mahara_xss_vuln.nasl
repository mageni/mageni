###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mahara_xss_vuln.nasl 12026 2018-10-23 08:22:54Z mmartin $
#
# Mahara <16.10.9, <17.04.7, <17.10.4 XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112255");
  script_version("$Revision: 12026 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 10:22:54 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-16 15:29:52 +0200 (Mon, 16 Apr 2018)");

  script_cve_id("CVE-2018-6182");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Mahara <16.10.9, <17.04.7, <17.10.4 XSS Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
  script_mandatory_keys("mahara/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Mahara and is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"Mahara 16.10 before 16.10.9 and 17.04 before 17.04.7 and 17.10 before 17.10.4");
  script_tag(name:"insight", value:"Mahara is vulnerable to bad input when TinyMCE is bypassed by POST packages.
  Therefore, Mahara should not rely on TinyMCE's code stripping alone but also clean input on the server /
  PHP side as one can create own packets of POST data containing bad content with which to hit the server.");
  script_tag(name:"solution", value:"Update Mahara to version 16.10.9, 17.04.7, 17.10.4 or later.");

  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1744789");
  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=8215");

  exit(0);
}

CPE = "cpe:/a:mahara:mahara";

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^16\.10\." && version_is_less(version:version, test_version:"16.10.9")) {
  VULN = TRUE;
  fix = "16.10.9";
} else if (version =~ "^17\.04\." && version_is_less(version:version, test_version:"17.04.7")) {
  VULN = TRUE;
  fix = "17.04.7";
} else if (version =~ "^17\.10\." && version_is_less(version:version, test_version:"17.10.4")) {
  VULN = TRUE;
  fix = "17.10.4";
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
