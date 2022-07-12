###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_mult_vuln_mar16.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# HP System Management Homepage Multiple Vulnerabilities(mar-2016)
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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807526");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-1993", "CVE-2016-1994", "CVE-2016-1995", "CVE-2016-1996");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-22 12:10:54 +0530 (Tue, 22 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("HP System Management Homepage Multiple Vulnerabilities(mar-2016)");

  script_tag(name:"summary", value:"The host is installed with HP System
  Management Homepage (SMH) and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain and modify sensitive information and also remote attackers to execute
  arbitrary code and to obtain sensitive information.");

  script_tag(name:"affected", value:"HP System Management Homepage before 7.5.4");

  script_tag(name:"solution", value:"Upgrade to HP System Management Homepage
  7.5.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05045763");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2301, 2381);
  script_xref(name:"URL", value:"http://www8.hp.com/us/en/products/server-software/product-detail.html?oid=344313");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!smhPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!smhVer = get_app_version(cpe:CPE, port:smhPort)){
  exit(0);
}

if(version_is_less(version:smhVer, test_version:"7.5.4"))
{
  report = report_fixed_ver(installed_version:smhVer, fixed_version:"7.5.4");
  security_message(data:report, port:smhPort);
  exit(0);
}
