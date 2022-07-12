###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_dos_vuln_aug11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Adobe Flash Media Server Remote Denial of Service Vulnerability (August-2011)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:flash_media_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801968");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-2011-2132");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Adobe Flash Media Server Remote Denial of Service Vulnerability (August-2011)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_fms_detect.nasl");
  script_require_ports("Services/www", 1111);
  script_mandatory_keys("Adobe/FMS/installed");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-20.html");
  script_xref(name:"URL", value:"http://securityswebblog.blogspot.com/2011/08/vulnerability-summary-for-cve-2011-2132.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of service.");
  script_tag(name:"affected", value:"Adobe Flash Media Server version before 3.5.7, and 4.x before 4.0.3");
  script_tag(name:"insight", value:"The flaw is due to an memory corruption via unspecified vectors,
  leading to a denial of service.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Media Server version 3.5.7, 4.0.3 or later.");
  script_tag(name:"summary", value:"This host is running Adobe Flash Media Server and is prone to
  denial of service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"3.5.7" ) ||
    version_in_range( version:vers, test_version:"4.0", test_version2:"4.0.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.5.7/4.0.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );