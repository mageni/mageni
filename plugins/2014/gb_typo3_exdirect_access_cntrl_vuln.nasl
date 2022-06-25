###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_exdirect_access_cntrl_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# TYPO3 ExtDirect Missing Access Control Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804212");
  script_version("$Revision: 11867 $");
  script_bugtraq_id(49072);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-07 16:28:55 +0530 (Tue, 07 Jan 2014)");
  script_name("TYPO3 ExtDirect Missing Access Control Vulnerability");


  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to consume any available
ExtDirect endpoint service..");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exist in ExtDirect, where an ExtDirect endpoints are not associated
with TYPO3 backend modules.");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.4.9, 4.5.4 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with TYPO3 and is prone missing access control
vulnerability.");
  script_tag(name:"affected", value:"TYPO3 version before 4.4.9 and 4.5.0 to 4.5.3");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45557/");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-CORE-sa-2011-001");
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
  if(version_is_less(version:typoVer, test_version:"4.4.9")||
     version_in_range(version:typoVer, test_version:"4.5.0", test_version2:"4.5.3"))
  {
    security_message(typoPort);
    exit(0);
  }
}
