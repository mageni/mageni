###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_buf_ovfl_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Asterisk CDR Buffer Overflow Vulnerability
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

CPE = 'cpe:/a:digium:asterisk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106737");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-10 13:40:13 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-7617");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk CDR Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a buffer overflow vulnerability in CDR's set user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"No size checking is done when setting the user field on a CDR. Thus, it is
possible for someone to use an arbitrarily large string and write past the end of the user field storage buffer.
This allows the possibility of remote code injection.");

  script_tag(name:"impact", value:"An authenticated remote attacker may execute arbitrary code.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 14.x and Certified Asterisk 13.13.");

  script_tag(name:"solution", value:"Upgrade to Version 13.14.1, 14.3.1, 13.13-cert3 or
later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-001.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.") {
  if (version =~ "^13\.13cert") {
    if (revcomp(a: version, b: "13.13cert3") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.13-cert3");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.14.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.14.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.3.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.3.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
