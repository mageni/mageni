###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zkteco_zktimeweb_mult_vuln.nasl 12698 2018-12-07 08:07:50Z mmartin $
#
# ZKTeco ZKTime Web Multiple Vulnerabilities
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

CPE = 'cpe:/a:zkteco:zktime_web';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140579");
  script_version("$Revision: 12698 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-07 09:07:50 +0100 (Fri, 07 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-12-05 12:03:16 +0700 (Tue, 05 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-17056", "CVE-2017-17057");
  script_bugtraq_id(102006, 102007);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ZKTeco ZKTime Web Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zkteco_zktimeweb_detect.nasl");
  script_mandatory_keys("zkteco_zktime/installed");

  script_tag(name:"summary", value:"ZKTeco ZKTime Web is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ZKTeco ZKTime Web is prone to multiple vulnerabilities:

  - Cross-site request forgery vulnerability (CVE-2017-17056)

  - Cross-site scripting vulnerability (CVE-2017-17057)");

  script_tag(name:"affected", value:"ZKTeco ZKTime Web version 2.0.1.12280 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/145159/ZKTeco-ZKTime-Web-2.0.1.12280-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/145160/ZKTeco-ZKTime-Web-2.0.1.12280-Cross-Site-Request-Forgery.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.0.1.12280")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
