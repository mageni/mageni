##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_mult_vuln_nov16_2.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# NTP.org 'ntp' Zero Origin Timestamp Regression Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106406");
  script_version("$Revision: 12313 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-03 11:18:33 +0700 (Fri, 03 Jun 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2016-7431");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTP.org 'ntp' Zero Origin Timestamp Regression Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("NTP/Installed", "NTP/Linux/Ver");
  script_require_udp_ports(123);

  script_tag(name:"summary", value:"ntpd is prone to a zero origin timestamp regression vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Zero Origin timestamp problems were fixed in ntp-4.2.8p6. However,
subsequent timestamp validation checks introduced a regression in the handling of some Zero origin timestamp
checks.");

  script_tag(name:"affected", value:"Version 4.2.8p8 and 4.3.93");

  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.8p9, 4.3.94 or later.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/633847");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");

port = 123;

if ("ntpd" >!< get_kb_item("NTP/Linux/FullVer"))
  exit(0);

if (!version = get_kb_item("NTP/Linux/Ver"))
  exit(0);

if (revcomp(a: version, b: "4.2.8p8") == 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8p9");
  security_message(port: port, data: report, proto:"udp");
  exit(0);
}

if (revcomp(a: version, b: "4.3.93") == 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.94");
  security_message(port: port, data: report, proto:"udp");
  exit(0);
}

exit(0);

