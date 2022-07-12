##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_dos_vuln_jan17_lin.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# ISC BIND 'buffer.c' Assertion Failure Denial of Service Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810263");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2016-2776");
  script_bugtraq_id(93188);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-06 12:10:51 +0530 (Fri, 06 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND 'buffer.c' Assertion Failure Denial of Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the 'buffer.c' script
  in named in ISC BIND does not properly construct responses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure and daemon exit)
  via a crafted query.");

  script_tag(name:"affected", value:"ISC BIND 9 before 9.9.9-P3, 9.10.x before
  9.10.4-P3, and 9.11.x before 9.11.0rc3 on Linux.");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.9.9-P3 or
  9.10.4-P3 or 9.11.0rc3 or later on Linux.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01419/0");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_unixoide");
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

version = ereg_replace( string:bindVer, pattern: ".", replace: "" );

if(bindVer =~ "^9")
{
  if(revcomp(a: bindVer, b: "9.9.9P3") < 0)
  {
    fix = "9.9.9-P3";
    VULN = TRUE;
  }
}

else if(bindVer =~ "^(9\.10)")
{
  if(revcomp(a: bindVer, b: "9.10.4P3") < 0)
  {
    fix = "9.10.4-P3";
    VULN = TRUE;
  }
}

else if(bindVer =~ "^(9\.11)")
{
  if(revcomp(a: bindVer, b: "9.11.0rc3") < 0)
  {
    fix = "9.11.0rc3";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:bindVer, fixed_version:fix);
  security_message(data:report, port:bindPort, proto:proto);
  exit(0);
}

exit(99);