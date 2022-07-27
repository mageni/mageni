###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_access_bypass_vuln_sep16_win.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# ownCloud Access Bypass Vulnerability Sep16 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809295");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2015-5954");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-23 15:52:23 +0530 (Fri, 23 Sep 2016)");
  script_name("ownCloud Access Bypass Vulnerability Sep16 (Windows)");

  script_tag(name:"summary", value:"The host is installed with ownCloud and
  is prone to access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the virtual
  filesystem does not consider that NULL is a valid getPath return value.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  authenticated users to bypass intended access restrictions and gain access to
  users files.");

  script_tag(name:"affected", value:"ownCloud Server before 6.0.9, 7.0.x
  before 7.0.7, and 8.0.x before 8.0.5 on Windows.");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 6.0.9 or
  7.0.7 or 8.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-011");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/installed", "Host/runs_windows");
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
  if(version_is_less(version:ownVer, test_version:"6.0.9"))
  {
    fix = "6.0.9";
    VULN = TRUE;
  }

  else if(version_in_range(version:ownVer, test_version:"7.0.0", test_version2:"7.0.6"))
  {
    fix = "7.0.7";
    VULN = TRUE;
  }

  else if(version_in_range(version:ownVer, test_version:"8.0.0", test_version2:"8.0.4"))
  {
    fix = "8.0.5";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:ownVer, fixed_version:fix);
    security_message(data:report, port:ownPort);
    exit(0);
  }
}
