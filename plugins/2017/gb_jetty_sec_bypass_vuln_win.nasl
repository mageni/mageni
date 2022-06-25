###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jetty_sec_bypass_vuln_win.nasl 12711 2018-12-07 21:05:48Z cfischer $
#
# Jetty < 9.4.6.20170531 Security Bypass Vulnerability (Windows)
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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108499");
  script_version("$Revision: 12711 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-07 22:05:48 +0100 (Fri, 07 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-08-01 11:31:21 +0700 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2017-9735");
  script_bugtraq_id(99104);
  script_name("Jetty < 9.4.6.20170531 Security Bypass Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Jetty/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/issues/1556");

  script_tag(name:"summary", value:"Jetty is prone to a security bypass vulnerability.");

  script_tag(name:"insight", value:"Jetty through is prone to a timing channel in util/security/Password.java,
  which makes it easier for remote attackers to obtain access by observing elapsed times before rejection of
  incorrect passwords.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Jetty version 9.4.x.");

  script_tag(name:"solution", value:"Update to version 9.4.6.v20170531 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^9\.4\.") {
  if (version_is_less(version: version, test_version: "9.4.6.20170531")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.4.6.20170531");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);