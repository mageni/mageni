###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_geovap_reliance_scada_xss_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Geovap Reliance SCADA XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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

CPE = "cpe:/a:geovap:reliance-scada";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112150");
  script_version("$Revision: 11977 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-07 08:23:03 +0100 (Thu, 07 Dec 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-16721");
  script_bugtraq_id(102031);

  script_name("Geovap Reliance SCADA XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_geovap_reliance_scada_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("geovap/reliance-scada/detected", "geovap/reliance-scada/version");

  script_tag(name:"summary", value:"This host is running Geovap Reliance SCADA and is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Successful exploitation of this vulnerability could allow an unauthenticated attacker
to inject arbitrary JavaScript in a specially crafted URL request that may allow for read/write access.");
  script_tag(name:"affected", value:"Reliance SCADA Version 4.7.3 Update 2 and prior.");
  script_tag(name:"solution", value:"Geovap has released Version 4.7.3 Update 3");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-334-02");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102031");
  script_xref(name:"URL", value:"https://www.reliance-scada.com/en/download");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_kb_item("geovap/reliance-scada/version"))
  exit(0);

if (version_is_less(version: version, test_version: "4.7.3 Update 3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.3 Update 3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

