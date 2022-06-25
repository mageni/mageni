###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_epesi_stored_xss_vuln.nasl 9565 2018-04-23 10:00:20Z ckuersteiner $
#
# EPESI Multiple Stored XSS Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:telaxus:epesi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112083");
  script_version("$Revision: 9565 $");
  script_cve_id("CVE-2017-14712", "CVE-2017-14713", "CVE-2017-14714", "CVE-2017-14715", "CVE-2017-14716", "CVE-2017-14717");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-23 12:00:20 +0200 (Mon, 23 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-10-16 13:53:00 +0200 (Mon, 16 Oct 2017)");
  script_name("EPESI Multiple Stored XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_epesi_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("epesi/installed", "epesi/revision");

  script_xref(name:"URL", value:"https://forum.epesibim.com/d/4956-security-issue-multiple-stored-xss-in-epesi-version-1-8-2-rev20170830");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42950/");

  script_tag(name:"summary", value:"EPESI is prone to multiple stored cross-site scripting (XSS) vulnerabilities
in various parameters.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow an auhenticated remote attacker
to store persistently executable scripts inside the application.");

  script_tag(name:"affected", value:"EPESI version 1.8.2-rev20170830 and below");

  script_tag(name:"solution", value:"Update to version 1.8.2-20171019 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);
rev = get_kb_item("epesi/revision");
if (!rev)
  exit(0);

if(version_is_less(version:vers, test_version:"1.8.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.8.2-20171019");
  security_message(port:port, data:report);
  exit(0);
}

if (version_is_equal(version: vers, test_version: "1.8.2")) {
  if (version_is_less(version: rev, test_version: "20171019")) {
    report = report_fixed_ver(installed_version: vers, installed_patch: rev, fixed_version: "1.8.2",
                              fixed_patch: "20171019");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
