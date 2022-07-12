###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ikarus_anti_virus_multiple_write_vulnerabilities.nasl 8493 2018-01-23 06:43:13Z ckuersteiner $
#
# IKARUS anti.virus Multiple Arbitrary/Out of Bounds Write Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112157");
  script_version("$Revision: 8493 $");
  script_cve_id("CVE-2017-14961", "CVE-2017-14962", "CVE-2017-14963", "CVE-2017-14964", "CVE-2017-14965",
      "CVE-2017-14966", "CVE-2017-14967", "CVE-2017-14968", "CVE-2017-14969");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:43:13 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-04 09:34:01 +0100 (Thu, 04 Jan 2018)");
  script_name("IKARUS anti.virus Multiple Arbitrary/Out of Bounds Write Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");

  script_tag(name:"summary", value:"This host is installed with IKARUS anti.virus
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect" , value:"Get the installed version with the help
  of the detection NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"In IKARUS anti.virus, various drivers contain Arbitrary or Out of Bounds Write vulnerabilities because of not validating input values from various sources.");

  script_tag(name:"affected", value:"IKARUS anti.virus before version 2.16.18.");

  script_tag(name:"solution", value:"Update IKARUS anti.virus to version 2.16.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.greyhathacker.net/?p=995");
  script_xref(name:"URL", value:"https://www.ikarussecurity.com/about-ikarus/security-blog/vulnerability-in-windows-antivirus-products-ik-sa-2017-0002/");

  script_dependencies("gb_ikarus_anti_virus_detect.nasl");
  script_mandatory_keys("ikarus/anti.virus/detected", "ikarus/anti.virus/version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ikarus:anti.virus";

if(!ver = get_app_version(cpe:CPE)) {
  exit(0);
}

if(version_is_less(version:ver, test_version:"2.16.18")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.16.18");
  security_message(data:report);
  exit(0);
}

exit(99);
