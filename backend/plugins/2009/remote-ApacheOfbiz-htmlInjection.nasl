###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-ApacheOfbiz-htmlInjection.nasl 14031 2019-03-07 10:47:29Z cfischer $
# Description: the script test the following vulnerabilities issues
# OFBiz Search_String Parameter HTML Injection Vulnerability (BID 21702)
# OFBiz Unspecified HTML Injection Vulnerability (BID 21529)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:open_for_business_project";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101020");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-22 20:27:36 +0200 (Wed, 22 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-6589", "CVE-2006-6587");
  script_bugtraq_id(21702, 21529);
  script_name("Apache Open For Business HTML injection vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "remote-detect-ApacheOfbiz.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("ApacheOFBiz/installed");

  script_tag(name:"solution", value:"Download the latest release form Apache Software Foundation (OFBiz) website.");

  script_tag(name:"summary", value:"The running Apache OFBiz is prone to the following security issue:

  OFBiz Search_String Parameter HTML Injection Vulnerability

  OFBiz Unspecified HTML Injection Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);

}

include("revisions-lib.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! ver = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( revcomp( a:ver, b:"3.0.0") <= 0 ){
  report = report_fixed_ver( installed_version:ver, fixed_version:"unknown");
  security_message(port:port, data:report);
  exit(0);
}

exit( 99 );