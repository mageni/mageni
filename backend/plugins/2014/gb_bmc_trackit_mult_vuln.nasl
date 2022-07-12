###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bmc_trackit_mult_vuln.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# BMC Track-It! Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = 'cpe:/a:bmc:bmc_track-it!';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105932");
  script_cve_id("CVE-2014-4872", "CVE-2014-4873", "CVE-2014-4874");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12083 $");

  script_name("BMC Track-It! Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70264");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70268");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70265");

  script_tag(name:"summary", value:"BMC Track-It! is prone to Multiple Vulnerabilities");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
to perform SQL injections, arbitrary file upload/download and code execution.");

  script_tag(name:"insight", value:"BMC Track-It! exposes several dangerous remote .NET services
on port 9010 without authentication. .NET remoting allows a user to invoke methods remotely and
retrieve their result (CVE-2014-4872).
An authenticated user can engage in blind SQL Injection by entering comparison operators in the
POST string for the /TrackItWeb/Grid/GetData page (CVE-2014-4873).
A remote authenticated user can download arbitrary files on the /TrackItWeb/Attachment page (CVE-2014-4874).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Hotfixes are available for CVE-2014-4873 and CVE-2014-4874. For
CVE-2014-4872 there is currently no hotfix available. As a workaround block all traffic from untrusted
networks to TCP/UDP ports 9010 to 9020.");

  script_tag(name:"affected", value:"BMC Track-It! version 11.3.0.355 and below.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-20 11:15:27 +0700 (Thu, 20 Nov 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_bmc_trackit_detect.nasl");
  script_mandatory_keys("bmctrackit/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_less_equal(version:version, test_version:"11.3.0.355")) {
  security_message(port:port);
  exit(0);
}
exit(0);
