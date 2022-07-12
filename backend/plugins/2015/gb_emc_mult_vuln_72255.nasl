###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_mult_vuln_72255.nasl 12131 2018-10-26 14:03:52Z mmartin $
#
# EMC M&R (Watch4net) Multiple Vulnerabilities
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

CPE = "cpe:/a:emc:watch4net";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105241");
  script_bugtraq_id(72259, 72256, 72255);
  script_cve_id("CVE-2015-0513", "CVE-2015-0515", "CVE-2015-0516");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_version("$Revision: 12131 $");

  script_name("EMC M&R (Watch4net) Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72255");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72256");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72259");

  script_tag(name:"impact", value:"A remote attacker could exploit the traversal vulnerability using directory-
traversal characters ('../') to access arbitrary files that contain sensitive information. Information harvested
may aid in launching further attacks.

An attacker may leverage the Arbitrary File Upload Vulnerability to upload arbitrary files to the affected computer.
This can result in arbitrary code execution within the context of the vulnerable application.

An attacker may leverage the Cross Site Scripting Vulnerabilities to execute arbitrary script code in the browser of an
unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication
credentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"EMC M&R (Watch4net) is prone to:
1. Credential Disclosure
It was discovered that EMC M&R (Watch4net) credentials of remote servers stored in Watch4net are encrypted using
a fixed hardcoded password. If an attacker manages to obtain a copy of the encrypted credentials, it is trivial
to decrypt them.

2. Directory Traversal
A path traversal vulnerability was found in EMC M&R (Watch4net) Device Discovery. This vulnerability allows an attacker
to access sensitive files containing configuration data, passwords, database records, log data, source code, and
program scripts and binaries.

3 Arbitrary File Upload Vulnerability
An attacker may leverage this issue to upload arbitrary files to the affected computer. This can result in arbitrary code
execution within the context of the vulnerable application.

4. Multiple Cross Site Scripting Vulnerabilities
Multiple cross site scripting vulnerabilities were found in EMC M&R (Watch4net) Centralized Management Console, Web Portal and
Alerting Frontend.");

  script_tag(name:"affected", value:"EMC M&R (Watch4net) before 6.5u1");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 16:03:52 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-20 10:57:29 +0100 (Fri, 20 Mar 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_emc_m_and_r_detect.nasl");
  script_require_ports("Services/www", 58080);
  script_mandatory_keys("emc_m_r/version");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( vers =  get_app_version( cpe:CPE, port:port ) )
{
  if( revcomp( a:vers, b:"6.5u1" ) < 0 )
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     6.5u1\n';

    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
