# OpenVAS Vulnerability Test
# $Id: remote-Leap_CMS_multi.nasl 14335 2019-03-19 14:46:57Z asteins $
# Description: This script multiple remote vulnerabilities on the Leap CMS
#
# remote-Leap_CMS_multi.nasl
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
#

include("revisions-lib.inc");


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101026");
  script_version("$Revision: 14335 $");
  script_cve_id("CVE-2009-1613", "CVE-2009-1614", "CVE-2009-1615");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-30 23:55:19 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Leap CMS Multiple Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);

  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "remote-detect-Leap_CMS.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("LeapCMS/installed");

  script_tag(name:"solution", value:"For the sql injection vulnerability, set your php configuration to magic_quotes_gpc = off,
for other vulnerabilities, it's recommended to download the latest stable version");
  script_tag(name:"summary", value:"The remote Leap CMS is affected by multiple remote vulnerabilities.");
  script_tag(name:"solution_type", value:"VendorFix");

exit(0);

}

include("misc_func.inc");

port = get_kb_item("LeapCMS/port");
version = get_kb_item("LeapCMS/version");
report = '';

if(!get_kb_item("LeapCMS/installed") || !port || !version)
	exit(0);
else {
	if(revcomp(a:version, b:"0.1.4") <= 0)
		report += "The current version " + version + " of LeapCMS is affected to multiple remote vulnerabilities";
}

if(report)
	security_message(port:port, data:report);
  exit(0);

exit(99);
