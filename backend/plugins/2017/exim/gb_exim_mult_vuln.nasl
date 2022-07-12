##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exim_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Exim Multiple RCE Vulnerabilities
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

CPE = 'cpe:/a:exim:exim';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140539");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-27 09:50:38 +0700 (Mon, 27 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-16943", "CVE-2017-16944");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim Multiple RCE Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("gb_exim_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("exim/installed");

  script_tag(name:"summary", value:"Exim is prone to multiple remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Exim is prone to multiple remote code execution vulnerabilities:

  - Use-after-free vulnerability while reading mail header (CVE-2017-16943)

  - Exim handles BDAT data incorrectly and leads to crash (CVE-2017-16944)");

  script_tag(name:"impact", value:"A remote attacker may execute arbitrary commands or conduct a denial of
service attack.");

  script_tag(name:"affected", value:"Exim version 4.88 and 4.89.");

  script_tag(name:"solution", value:"Apply the provided patch or update to version 4.90 or later. As a
mitigation set 'chunking_advertise_hosts = ' in the Exim configuration.");

  script_xref(name:"URL", value:"https://lists.exim.org/lurker/message/20171125.034842.d1d75cac.en.html");
  script_xref(name:"URL", value:"https://bugs.exim.org/show_bug.cgi?id=2199");
  script_xref(name:"URL", value:"https://bugs.exim.org/show_bug.cgi?id=2201");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.88", test_version2: "4.89")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
