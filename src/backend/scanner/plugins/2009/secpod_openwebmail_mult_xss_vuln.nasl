###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openwebmail_mult_xss_vuln.nasl 14121 2019-03-13 06:21:23Z ckuersteiner $
#
# OpenWebMail Multiple XSS Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:openwebmail.acatysmoof:openwebmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900943");
  script_version("$Revision: 14121 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 07:21:23 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-7202");
  script_bugtraq_id(25175);

  script_name("OpenWebMail Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OpenWebMail/detected");

  script_xref(name:"URL", value:"http://freshmeat.net/projects/openwebmail/releases/270453");
  script_xref(name:"URL", value:"http://pridels-team.blogspot.com/2007/08/openwebmail-multiple-xss-vuln.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary
  web script or HTML via unknown vectors and conduct cross-sites attacks.");

  script_tag(name:"affected", value:"OpenWebMail versions prior to 2.53.");

  script_tag(name:"insight", value:"The vulnerability is caused because the application does not
  sanitise the user supplied data.");

  script_tag(name:"solution", value:"Upgrade to version 2.53 or later.");

  script_tag(name:"summary", value:"This host is installed with OpenWebMail and is prone to
  multiple cross-sites scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2.53" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.53" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
