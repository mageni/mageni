###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_unspecified_vuln02_july16.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Oracle GlassFish Server Unspecified Vulnerability -02 July16
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808706");
  script_version("$Revision: 12338 $");
  script_cve_id("CVE-2016-5477");
  script_bugtraq_id(92032);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-22 12:27:52 +0530 (Fri, 22 Jul 2016)");
  script_name("Oracle GlassFish Server Unspecified Vulnerability -02 July16");

  script_tag(name:"summary", value:"This host is running Oracle GlassFish Server
  and is prone to unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the Administration
  sub-component.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality via unknown vectors.");

  script_tag(name:"affected", value:"Oracle GlassFish Server version 2.1.1,
  and 3.0.1");

  script_tag(name:"solution", value:"Apply the patches from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!dbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if (!dbVer = get_app_version(cpe:CPE, port:dbPort)){
  exit(0);
}

if(version_is_equal(version:dbVer, test_version:"2.1.1") ||
   version_is_equal(version:dbVer, test_version:"3.0.1"))
{
  report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
  security_message(data:report, port:dbPort);
  exit(0);
}

exit(99);
