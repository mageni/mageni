###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wd_wdtv_rce_vuln.nasl 13716 2019-02-18 04:31:31Z ckuersteiner $
#
# Western Digital WD TV Live Hub RCE Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = 'cpe:/a:western_digital:wdtv_live_hub';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141284");
  script_version("$Revision: 13716 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 05:31:31 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-07-09 14:38:27 +0200 (Mon, 09 Jul 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-1151");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Western Digital WD TV Live Hub RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_wdtv_detect.nasl");
  script_mandatory_keys("wd_wdtv/detected");

  script_tag(name:"summary", value:"The web server on Western Digital TV Live Hub 3.12.13 allow unauthenticated
remote attackers to execute arbitrary code or cause denial of service via crafted HTTP requests to
toServerValue.cgi.");

  script_tag(name:"affected", value:"Western Digital TV Live Hub 3.12.13 and probably prior.");

  script_tag(name:"solution", value:"No known solution is available as of 18th February, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"vuldetect", value:"Checks the firmware version.");

  script_xref(name:"URL", value:'https://www.tenable.com/security/research/tra-2018-14');

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "3.12.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
