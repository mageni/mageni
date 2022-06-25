###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_edr810_info_disc_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Moxa EDR-810 Information Disclosure Vulnerability
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

CPE = "cpe:/h:moxa:edr-810";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106623");
  script_version("$Revision: 11977 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-28 14:46:57 +0700 (Tue, 28 Feb 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-8346");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moxa EDR-810 Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moxa_edr_devices_web_detect.nasl");
  script_mandatory_keys("moxa_edr/detected");

  script_tag(name:"summary", value:"Moxa EDR-810 devices are prone to a information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to access several config and log files.");

  script_tag(name:"insight", value:"By accessing a specific URL on the web server, a malicious user is able to
access configuration and log files. These files are just available if a user or admin exported the files first.");

  script_tag(name:"impact", value:"A unauthenticated attacker may gain sensitive information about the device.");

  script_tag(name:"affected", value:"Moxa EDR-810 using firmware versions prior to V3.13");

  script_tag(name:"solution", value:"Update the firmware to V3.13 or later.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-294-01");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = make_array("Index.*Bootup.*Date.*Time", "/MOXA_LOG.ini",
                   "! ---------- EDR-810", "/MOXA_CFG.ini",
                   "Content-type: text/plain", "/MOXA_All_LOG.tar.gz",
                   "Index.*Date.*Time.*Event", "/MOXA_IPSec_LOG.ini",
                   "Index.*Date.*Time.*Event", "/MOXA__Firewall_LOG.ini");

report = "The following config and log files are accessible:\n\n";

foreach file (keys(files)) {
  url = dir + files[file];
  if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE)) {
    report += report_vuln_url(port: port, url: url, url_only: TRUE) + "\n";
    vuln = TRUE;
  }
}

if (vuln)
  security_message(port: port, data: report);

exit(0);
