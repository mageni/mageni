###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_vuln02_feb15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# ownCloud Multiple Vulnerabilities -02 Feb15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805280");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-9046", "CVE-2014-9043", "CVE-2014-9042", "CVE-2014-9041");
  script_bugtraq_id(71383, 71389, 71373, 71369);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-19 15:54:16 +0530 (Thu, 19 Feb 2015)");
  script_name("ownCloud Multiple Vulnerabilities -02 Feb15");

  script_tag(name:"summary", value:"The host is installed with ownCloud and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error in the 'OC_Util::getUrlContent' function that is due to it allows
  redirects from other protocols (such as file://)

  - An error in the 'ldap_bind' function in libldap that is triggered when
  handling a password that contains NULL bytes.

  - The bookmark application does not validate input to bookmarks before
  returning it to users.

  - An error in the bookmarks application as HTTP requests do not require
  multiple steps, explicit confirmation, or a unique token when performing
  certain sensitive actions.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to perform a cross-site request forgery attack, execute
  arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server, bypass authentication
  mechanisms and gain access to arbitrary local files.");

  script_tag(name:"affected", value:"ownCloud Server 5.x before 5.0.18, 6.x
  before 6.0.6, and 7.x before 7.0.3");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 5.0.18 or 6.0.6
  or 7.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-027");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-028");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-020");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-023");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");
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

if(ownVer =~ "^(5|6|7)")
{
  if(version_in_range(version:ownVer, test_version:"5.0.0", test_version2:"5.0.17"))
  {
    fix = "5.0.18";
    VULN = TRUE;
  }

  if(version_in_range(version:ownVer, test_version:"6.0.0", test_version2:"6.0.5"))
  {
    fix = "6.0.6";
    VULN = TRUE;
  }

  if(version_in_range(version:ownVer, test_version:"7.0.0", test_version2:"7.0.2"))
  {
    fix = "7.0.3";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = 'Installed version: ' + ownVer + '\n' +
             'Fixed version:     ' + fix + '\n';

    security_message(port:ownPort, data:report);
    exit(0);
  }
}

exit(99);