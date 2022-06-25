###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_private_messages_auth_bypass_vuln.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# vBulletin 'Private Messages' Authentication Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811796");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2015-3419");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-10-04 13:06:11 +0530 (Wed, 04 Oct 2017)");
  script_name("vBulletin 'Private Messages' Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with vBulletin and is prone
  to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an input validation
  failure");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject messages into existing conversations without
  authorization.");

  script_tag(name:"affected", value:"vBulletin versions 5.x through 5.1.6");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); ## Not possible to detect the patched versions
  script_xref(name:"URL", value:"https://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/4319488-security-patch-released-for-vbulletin-5-1-4-5-1-6-and-vbulletin-cloud");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vBulletin/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://members.vbulletin.com/patches.php");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! bulPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! bulVers = get_app_version( cpe:CPE, port:bulPort ) ) exit( 0 );

if(version_in_range( version:bulVers, test_version:"5.0", test_version2:"5.1.6"))
{
  report = report_fixed_ver(installed_version:bulVers, fixed_version:"Apply Patch" );
  security_message(port:bulPort, data:report);
  exit(0);
}
exit(0);
