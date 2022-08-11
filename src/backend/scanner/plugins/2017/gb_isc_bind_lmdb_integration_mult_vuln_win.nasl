##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_lmdb_integration_mult_vuln_win.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# ISC BIND LMDB Integration Multiple Vulnerabilities (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810957");
  script_version("$Revision: 11863 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-21 17:50:15 +0530 (Wed, 21 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ISC BIND LMDB Integration Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to BIND's use of LMDB.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause some issues regarding zone operations and an unexpected
  application termination.");

  script_tag(name:"affected", value:"ISC BIND 9.11.0 -> 9.11.1.Px (all versions of
  BIND 9.11.0 and 9.11.1) on Windows.");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.11.2 or later
  on Windows.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01497");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_windows");
  script_xref(name:"URL", value:"https://www.isc.org");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if( ! bindPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:bindPort ) ) exit( 0 );

bindVer = infos["version"];
proto = infos["proto"];

if(bindVer =~ "^(9\.11)")
{
  if(revcomp(a: bindVer, b: "9.11.2") < 0)
  {
    report = report_fixed_ver(installed_version:bindVer, fixed_version:"9.11.2");
    security_message(data:report, port:bindPort, proto:proto);
    exit(0);
  }
}

exit(99);
