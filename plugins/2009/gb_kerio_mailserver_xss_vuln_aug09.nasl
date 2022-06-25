###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_mailserver_xss_vuln_aug09.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Kerio MailServer WebMail 'Integration' Page XSS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:kerio:kerio_mailserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800675");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-2636");
  script_bugtraq_id(35264);
  script_name("Kerio MailServer WebMail 'Integration' Page XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kerio_mailserver_detect.nasl");
  script_mandatory_keys("KerioMailServer/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35392");
  script_xref(name:"URL", value:"http://www.kerio.com/support/security-advisories#0906");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jun/1022348.html");

  script_tag(name:"impact", value:"Successful exploitation could result in insertion of arbitrary HTML and script
  code in the user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Kerio MailServer version 6.6.0 before 6.6.2 Patch 3 and
  6.7.0 before 6.7.0 Patch 1.");

  script_tag(name:"insight", value:"Issue is due to certain unspecified input passed to the integration page of
  the WebMail component which is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to Kerio MailServer 6.6.2 Patch 3 or 6.7.0 Patch 1 or later.");

  script_tag(name:"summary", value:"The host is running Kerio MailServer and is prone to Cross-Site
  Scripting vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE, version_regex:"^6\." ) )
  exit( 0 );

if( vers =~ "^6\.6" && version_is_less( version:vers, test_version:"6.6.2.patch3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.6.2 Patch 3" );
  security_message( port:0, data:report );
  exit( 0 );
} else if( vers =~ "^6\.7" && version_is_less( version:vers, test_version:"6.7.0.patch1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.7.0 Patch 1" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );