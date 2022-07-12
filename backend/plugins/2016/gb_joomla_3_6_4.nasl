###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_3_6_4.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Joomla Core < 3.6.4 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140018");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2016-8870", "CVE-2016-8869", "CVE-2016-9081");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-25 17:01:05 +0200 (Tue, 25 Oct 2016)");

  script_name("Joomla Core < 3.6.4 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The remote Joomla installation is prone to three critical security
vulnerabilities.

  1. Inadequate checks allows for users to register on a site when registration has been disabled.

  2. Incorrect use of unfiltered data allows for users to register on a site with elevated privileges.

  3. Incorrect use of unfiltered data allows for existing user accounts to be modified to include
  resetting their username, password, and user group assignments.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to inadequate filtering of request data.");

  script_tag(name:"affected", value:"Joomla core versions 3.4.4 through 3.6.3");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.6.4 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.joomla.org/announcements/release-news/5678-joomla-3-6-4-released.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! ver = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:ver, test_version:"3.4.4", test_version2:"3.6.3" ) )
{
  report = report_fixed_ver( installed_version:ver, fixed_version:"3.6.4" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
