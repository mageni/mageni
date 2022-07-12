###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_web_form_hash_collision_dos_vuln_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# PHP Web Form Hash Collision Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802408");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-4885", "CVE-2012-0788", "CVE-2012-0789");
  script_bugtraq_id(51193, 51952, 52043);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-03 16:47:40 +0530 (Tue, 03 Jan 2012)");
  script_name("PHP Web Form Hash Collision Denial of Service Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial
  of service via a specially crafted form sent in a HTTP POST request.");

  script_tag(name:"affected", value:"PHP Version 5.3.8 and prior.");

  script_tag(name:"insight", value:"The flaws are due to an error in,

  - A hash generation function when hashing form posts and updating a hash
    table. This can be exploited to cause a hash collision resulting in high
    CPU consumption via a specially crafted form sent in a HTTP POST request.

  - PDORow implementation, when interacting with the session feature.

  - timezone functionality, when handling php_date_parse_tzfile cache.");

  script_tag(name:"solution", value:"Upgrade PHP to 5.3.9 or later.");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone to remote denial of
  service vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47404");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/903934");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=53502");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=55776");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72021");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18305/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18296/");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2011-003.html");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=321040");

  script_xref(name:"URL", value:"http://php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less_equal(version:phpVer, test_version:"5.3.8")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.9");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
