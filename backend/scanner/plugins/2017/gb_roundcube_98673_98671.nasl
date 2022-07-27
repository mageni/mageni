###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_roundcube_98673_98671.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# Roundcube Webmail CVE-2015-5381 - CVE-2015-5383 Multiple Vulnerabilities
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

CPE = 'cpe:/a:roundcube:webmail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108170");
  script_version("$Revision: 12083 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-30 15:00:00 +0200 (Tue, 30 May 2017)");
  script_cve_id("CVE-2015-5381", "CVE-2015-5382", "CVE-2015-5383");
  script_bugtraq_id(98671, 98673);
  script_name("Roundcube Webmail CVE-2015-5381 - CVE-2015-5383 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("roundcube/installed");

  script_tag(name:"summary", value:"This host is installed with Roundcube Webmail and is prone to
  multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws exists:

  - XSS vulnerability in _mbox argument

  - security improvement in contact photo handling

  - potential info disclosure from temp directory");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to:

  - execute arbitrary script code in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based authentication credentials
  and to launch other attacks.

  - gain access to sensitive information. Information obtained may lead to further attacks.");

  script_tag(name:"affected", value:"Roundcube Webmail versions prior to 1.0.6 and 1.1.x
  versions prior to 1.1.2.");

  script_tag(name:"solution", value:"Upgrade Roundcube Webmail to 1.0.6 or 1.1.2 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2015/06/05/updates-1.1.2-and-1.0.6-released");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.0.6" ) ) {
  vuln = TRUE;
  fix = "1.0.6";
}

if( version_in_range( version:vers, test_version:"1.1.0", test_version2:"1.1.1" ) ) {
  vuln = TRUE;
  fix = "1.1.2";
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
