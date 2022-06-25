###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortinet_FortiAuthenticator_72378.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Fortinet FortiAuthenticator Appliance Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:fortinet:fortiauthenticator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105228");
  script_bugtraq_id(72378);
  script_cve_id("CVE-2015-1456", "CVE-2015-1455", "CVE-2015-1457", "CVE-2015-1459", "CVE-2015-1458");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12106 $");

  script_name("Fortinet FortiAuthenticator Appliance Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72378");
  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-15-003");

  script_tag(name:"affected", value:"FortiAuthenticator lower than 3.2.1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to FortiAuthenticator 3.2.1 or higher.");
  script_tag(name:"summary", value:"Fortinet FortiAuthenticator Appliance is prone to the following
multiple security vulnerabilities:

1. A cross-site scripting vulnerability
2. A command-execution vulnerability
3. Multiple information-disclosure vulnerabilities");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary script code
in the context of the vulnerable site, potentially allowing the attacker to steal cookie-based authentication
credentials, execute arbitrary commands and gain access to potentially sensitive information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-02 10:40:16 +0100 (Mon, 02 Mar 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_forti_authenticator_version.nasl");
  script_mandatory_keys("fortiauthenticator/version");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

include("version_func.inc");

vers = get_app_version( cpe:CPE );
if( ! vers )
  vers = get_kb_item("fortiauthenticator/version");

if( ! vers ) exit( 0 );

if( version_is_less( version: vers, test_version: "3.2.1" ) )
{
  report = 'Installed Version: ' + vers + '\nFixed Version:     3.2.1\n';
  security_message( port:0, data:report );
  exit (0 );
}

exit( 99 );

