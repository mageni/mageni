###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_mult_vuln_may16.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# HP System Management Homepage Multiple Vulnerabilities(may-2016)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807598");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2011-4969", "CVE-2015-3194", "CVE-2015-3195", "CVE-2016-0705",
                "CVE-2016-0799", "CVE-2016-2842", "CVE-2015-3237", "CVE-2015-7995",
                "CVE-2015-8035", "CVE-2007-6750", "CVE-2016-2015");
  script_bugtraq_id(58458, 78623, 78626, 75387, 77325, 77390, 21865);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-19 15:47:50 +0530 (Thu, 19 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("HP System Management Homepage Multiple Vulnerabilities(may-2016)");

  script_tag(name:"summary", value:"The host is installed with HP System
  Management Homepage (SMH) and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain and modify sensitive information and also remote attackers to execute
  arbitrary code and to obtain sensitive information.");

  script_tag(name:"affected", value:"HP System Management Homepage before 7.5.5");

  script_tag(name:"solution", value:"Upgrade to HP System Management Homepage
  7.5.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05111017");

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

if(version_is_less(version:smhVer, test_version:"7.5.5"))
{
  report = report_fixed_ver(installed_version:smhVer, fixed_version:"7.5.5");
  security_message(data:report, port:smhPort);
  exit(0);
}
