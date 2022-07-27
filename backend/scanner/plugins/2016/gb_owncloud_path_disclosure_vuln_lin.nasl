###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_path_disclosure_vuln_lin.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# ownCloud Path Disclosure Vulnerability Feb16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807401");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-1501");
  script_bugtraq_id(80382);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-02 15:04:46 +0530 (Wed, 02 Mar 2016)");
  script_name("ownCloud Path Disclosure Vulnerability Feb16 (Linux)");

  script_tag(name:"summary", value:"The host is installed with ownCloud and
  is prone to path disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an owncloud return
  exception error messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated adversary to gain information about the installation path of
  the ownCloud instance.");

  script_tag(name:"affected", value:"ownCloud Server 8.x before 8.0.9 and 8.1.x
  before 8.1.4 on Linux.");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 8.0.9 or 8.1.4
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2016-004");

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

if(ownVer =~ "^8")
{
  if(version_in_range(version:ownVer, test_version:"8.0.0", test_version2:"8.0.8"))
  {
    fix = "8.0.9";
    VULN = TRUE;
  }

  else if(version_in_range(version:ownVer, test_version:"8.1.0", test_version2:"8.1.3"))
  {
    fix = "8.1.4";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:ownVer, fixed_version:fix);
    security_message(data:report, port:ownPort);
    exit(0);
  }
}
