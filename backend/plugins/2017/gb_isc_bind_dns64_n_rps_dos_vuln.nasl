##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_dns64_n_rps_dos_vuln.nasl 13595 2019-02-12 08:06:21Z mmartin $
#
# ISC BIND DNS64 and RPZ Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.810547");
  script_version("$Revision: 13595 $");
  script_cve_id("CVE-2017-3135");
  script_bugtraq_id(96150);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 09:06:21 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-02-27 13:12:12 +0530 (Mon, 27 Feb 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND DNS64 and RPZ Denial of Service Vulnerability");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to using both DNS64
  and RPZ to rewrite query responses, query processing can resume in an
  inconsistent state.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause an INSIST assertion failure (and subsequent abort) or an
  attempt to read through a NULL pointer.  On most platforms a NULL pointer
  read leads to a segmentation fault (SEGFAULT), which causes the process to
  be terminated.");

  script_tag(name:"affected", value:"ISC BIND versions 9.8.8, 9.9.3-S1 through 9.9.9-S7,
  9.9.3 through 9.9.9-P5, 9.9.10b1, 9.10.0 through 9.10.4-P5, 9.10.5b1, 9.11.0
  through 9.11.0-P2 and 9.11.1b1");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.9.9-P6 or
  9.10.4-P6 or 9.11.0-P3 or  9.9.9-S8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01453");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");
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

if(bindVer =~ "^9")
{
  if (bindVer =~ "9\.9\.[3-9]\.S[1-7]")
  {
    fix = "9.9.9-S8";
    VULN = TRUE;
  }

  else if(bindVer =~ "^(9\.9\.[3-9])")
  {
    if(revcomp(a: bindVer, b: "9.9.9.P6") < 0)
    {
      fix = "9.9.9-P6";
      VULN = TRUE;
    }
  }
  else if(bindVer =~ "^(9\.10\.)")
  {
    if(revcomp(a: bindVer, b: "9.10.4.P6") < 0)
    {
      fix = "9.10.4-P6";
      VULN = TRUE;
    }
  }
  else if(bindVer =~ "^(9\.11\.0)")
  {
    if(revcomp(a: bindVer, b: "9.11.0.P3") < 0)
    {
      fix = "9.11.0-P3";
      VULN = TRUE;
    }
  }
  else if(version_is_equal(version:bindVer, test_version:"9.11.1b1") ||
          version_is_equal(version:bindVer, test_version:"9.10.5b1") ||
          version_is_equal(version:bindVer, test_version:"9.8.8"))
  {
    fix = "9.11.0-P3 or 9.10.4-P6 or 9.9.9-P6 or 9.9.9-S8";
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
