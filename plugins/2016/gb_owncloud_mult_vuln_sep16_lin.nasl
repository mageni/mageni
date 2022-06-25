###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_vuln_sep16_lin.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# ownCloud Multiple Vulnerabilities Sep16 (Linux)
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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809293");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2015-4718", "CVE-2015-4717");
  script_bugtraq_id(76162, 76161);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-23 15:29:08 +0530 (Fri, 23 Sep 2016)");
  script_name("ownCloud Multiple Vulnerabilities Sep16 (Linux)");

  script_tag(name:"summary", value:"The host is installed with ownCloud and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - The external SMB storage of ownCloud was not properly neutralizing all
    special elements.

  - The filename sanitization component does not properly handle $_GET
    parameters cast by PHP to an array");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  authenticated users to execute arbitrary SMB commands and to cause a denial
  of service.");

  script_tag(name:"affected", value:"ownCloud Server before 6.0.8, 7.0.x
  before 7.0.6, and 8.0.x before 8.0.4 on Linux.");

  script_tag(name:"solution", value:"Upgrade ownCloud server 6.0.8, 7.0.6, 8.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-008");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-007");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://owncloud.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ownPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ownVer = get_app_version(cpe:CPE, port:ownPort)){
  exit(0);
}

if(ownVer =~ "^(8|7|6)")
{
  if(version_is_less(version:ownVer, test_version:"6.0.8"))
  {
    fix = "6.0.8";
    VULN = TRUE;
  }

  else if(version_in_range(version:ownVer, test_version:"7.0.0", test_version2:"7.0.5"))
  {
    fix = "7.0.6";
    VULN = TRUE;
  }

  else if(version_in_range(version:ownVer, test_version:"8.0.0", test_version2:"8.0.3"))
  {
    fix = "8.0.4";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:ownVer, fixed_version:fix);
    security_message(data:report, port:ownPort);
    exit(0);
  }
}

