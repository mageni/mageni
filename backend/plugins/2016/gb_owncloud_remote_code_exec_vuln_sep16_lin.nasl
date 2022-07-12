###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_remote_code_exec_vuln_sep16_lin.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# ownCloud Remote Code Execution Vulnerability Sep16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809285");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2015-7699");
  script_bugtraq_id(77329);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-23 13:05:18 +0530 (Fri, 23 Sep 2016)");
  script_name("ownCloud Remote Code Execution Vulnerability Sep16 (Linux)");

  script_tag(name:"summary", value:"The host is installed with ownCloud and
  is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper check
  of the mount point options provided by a user via the web front end in the
  'files_external' app.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  authenticated users to instantiate arbitrary classes and possibly execute
  arbitrary code.");

  script_tag(name:"affected", value:"ownCloud Server before 7.0.9, 8.0.x
  before 8.0.7, and 8.1.x before 8.1.2 on Linux.");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 7.0.9 or 8.0.7
  or 8.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-018");

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

if(ownVer =~ "^(8|7)")
{
  if(version_is_less(version:ownVer, test_version:"7.0.9"))
  {
    fix = "7.0.9";
    VULN = TRUE;
  }

  else if(version_in_range(version:ownVer, test_version:"8.0.0", test_version2:"8.0.6"))
  {
    fix = "8.0.7";
    VULN = TRUE;
  }

  else if(version_in_range(version:ownVer, test_version:"8.1.0", test_version2:"8.1.1"))
  {
    fix = "8.1.2";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:ownVer, fixed_version:fix);
    security_message(data:report, port:ownPort);
    exit(0);
  }
}
