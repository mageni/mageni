###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_server_dos_vuln_apr16.nasl 12153 2018-10-29 13:38:34Z cfischer $
#
# Oracle GlassFish Server Denial of Service Vulnerability April16
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

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807565");
  script_version("$Revision: 12153 $");
  script_cve_id("CVE-2015-7182");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 14:38:34 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-27 10:47:16 +0530 (Wed, 27 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle GlassFish Server Denial of Service Vulnerability April16");

  script_tag(name:"summary", value:"This host is installed with  Oracle GlassFish
  Server is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a heap-based buffer
  overflow error in Oracle GlassFish Server component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (application crash) or possibly
  execute arbitrary code.");

  script_tag(name:"affected", value:"Oracle GlassFish Server version 2.1.1.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");
  script_require_ports("Services/www", 8080, 8181, 4848);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!oraclePort = get_app_port(cpe:CPE)){
  exit(0);
}

if (!oracleVer = get_app_version(cpe:CPE, port:oraclePort)){
  exit(0);
}

if (version_is_equal(version:oracleVer, test_version:"2.1.1")) {
  report = report_fixed_ver(installed_version:oracleVer, fixed_version:"Apply the patch");
  security_message(data:report, port:oraclePort);
  exit(0);
}

exit(99);
