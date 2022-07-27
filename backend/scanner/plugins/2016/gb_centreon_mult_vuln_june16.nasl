###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_centreon_mult_vuln_june16.nasl 11811 2018-10-10 09:55:00Z asteins $
#
# Centreon 'POST' Parameter Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:centreon:centreon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807337");
  script_version("$Revision: 11811 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 11:55:00 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-07 16:34:49 +0530 (Tue, 07 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Centreon 'POST' Parameter Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Centreon
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An insufficient validation of user supplied input via post parameter
    'img_comment' to 'main.php' script.

  - An improper verification of uploaded files via the 'filename' POST
    parameter.

  - The validity checks are not performed to verify the HTTP requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to perform certain actions with administrative privileges, to execute
  arbitrary code into user's browser session on the affected site.");

  script_tag(name:"affected", value:"Centreon version 2.6.1");

  script_tag(name:"solution", value:"Upgrade to Centreon 2.6.3 or 2.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38339");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("centreon_detect.nasl");
  script_mandatory_keys("centreon/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.centreon.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!cenPort = get_app_port(cpe:CPE))
  exit(0);

if (!cenVer = get_app_version(cpe:CPE, port:cenPort))
  exit(0);

if (version_is_equal(version:cenVer, test_version:"2.6.1")) {
  report = report_fixed_ver(installed_version:cenVer, fixed_version:"2.6.3 or 2.7 or later");
  security_message(data:report, port:cenPort);
  exit(0);
}

exit(0);
