###############################################################################
# OpenVAS Vulnerability Test
#
# Opentaps Search_String Parameter HTML Injection Vulnerability (BID 21702)
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:apache:opentaps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101022");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-24 21:45:26 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-6589");
  script_bugtraq_id(21702);
  script_name("Opentaps ERP + CRM Search_String Parameter HTML injection vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Web application abuses");
  script_dependencies("remote-detect-Opentaps_ERP_CRM.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("OpentapsERP/installed");

  script_tag(name:"solution", value:"Download the latest release from the opentaps website.");

  script_tag(name:"summary", value:"The running Opentaps ERP + CRM is prone to the HTML Injection Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("revisions-lib.inc");
include("misc_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( port:port, cpe:CPE ) ) exit( 0 );

if( revcomp( a:vers, b:"0.9.3" ) <= 0 ) {
  report = "The current Opentaps version " + vers + " is affected by a Search_String Parameter HTML injection vulnerability.";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );