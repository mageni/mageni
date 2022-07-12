###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_xss_n_cmd_exec_vuln.nasl 12952 2019-01-07 06:54:36Z ckuersteiner $
#
# TWiki XSS and Command Execution Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:twiki:twiki';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800320");
  script_version("$Revision: 12952 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-07 07:54:36 +0100 (Mon, 07 Jan 2019) $");
  script_tag(name:"creation_date", value:"2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5304", "CVE-2008-5305");
  script_bugtraq_id(32668, 32669);

  script_name("TWiki XSS and Command Execution Vulnerabilities");

  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("twiki/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary script code or
  commands. This could let attackers steal cookie-based authentication credentials or compromise the affected
  application.");

  script_tag(name:"affected", value:"TWiki, TWiki version prior to 4.2.4.");
  script_tag(name:"insight", value:"The flaws are due to,

  - %URLPARAM{}% variable is not properly sanitized which lets attackers
    conduct cross-site scripting attack.

  - %SEARCH{}% variable is not properly sanitised before being used in an
    eval() call which lets the attackers execute perl code through eval
    injection attack.");

  script_tag(name:"solution", value:"Upgrade to version 4.2.4 or later.");

  script_tag(name:"summary", value:"The host is running TWiki and is prone to Cross-Site Scripting
  (XSS) and Command Execution Vulnerabilities.");

  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev.SecurityAlert-CVE-2008-5304");
  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2008-5305");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"4.2.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.2.4" );
  security_message(port:port, data:report );
  exit( 0 );
}

exit( 99 );
