###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_parse_url_ssrf_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# vBulletin 'parse_url' Server Side Request Forgery (SSRF) Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108145");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-7569");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-19 07:57:33 +0200 (Wed, 19 Apr 2017)");
  script_name("vBulletin 'parse_url' Server Side Request Forgery (SSRF) Vulnerability");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vBulletin/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/4367744-vbulletin-5-3-0-connect-is-now-available");

  script_tag(name:"summary", value:"This host is installed with vBulletin and is prone
  to a server side request forgery vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote attackers can bypass the CVE-2016-6483 patch and
  conduct SSRF attacks by leveraging the behavior of the PHP parse_url function, aka VBV-17037.");

  script_tag(name:"affected", value:"vBulletin versions before 5.3.0.");

  script_tag(name:"solution", value:"Upgrade to vBulletin version 5.3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.vbulletin.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.3.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.3.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
