###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_fal_mult_vuln.nasl 2014-01-06 12:50:36Z jan$
#
# TYPO3 File Abstraction Layer Multiple Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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
CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804205");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-4320", "CVE-2013-4321");
  script_bugtraq_id(62255, 62257);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-06 12:50:36 +0530 (Mon, 06 Jan 2014)");
  script_name("TYPO3 File Abstraction Layer Multiple Vulnerabilities");


  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
or read sensitive information.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exist in the File Abstraction Layer, which implements partial
permissions for copying, deleting, and moving files and it does not properly
handle denied file extension names that contain special characters.");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 6.0.9, 6.1.4 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with TYPO3 and is prone to multiple vulnerabilities.");
  script_tag(name:"affected", value:"TYPO3 version 6.0.0 to 6.0.8, 6.1.0 to 6.1.3");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54679/");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2013-003");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");


if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(typoVer = get_app_version(cpe:CPE, port:typoPort))
{
  if( typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+" ) exit( 0 ); # Version is not exact enough
  if(version_in_range(version:typoVer, test_version:"6.0.0", test_version2:"6.0.8") ||
     version_in_range(version:typoVer, test_version:"6.1.0", test_version2:"6.1.3"))
  {
    security_message(typoPort);
    exit(0);
  }
}
