###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netmri_50646.nasl 11306 2018-09-10 14:58:09Z mmartin $
#
# Infoblox NetMRI Admin Login Page Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
CPE = "cpe:/a:infoblox:netmri";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103576");
  script_bugtraq_id(50646);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11306 $");

  script_name("Infoblox NetMRI Admin Login Page Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50646");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Nov/158");
  script_xref(name:"URL", value:"http://www.infoblox.com/en/products/netmri.html");

  script_tag(name:"last_modification", value:"$Date: 2018-09-10 16:58:09 +0200 (Mon, 10 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-09-25 12:37:48 +0200 (Tue, 25 Sep 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_netmri_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("netMRI/detected");
  script_tag(name:"solution", value:"Reportedly the vendor has released an update to fix the issue.");
  script_tag(name:"summary", value:"Infoblox NetMRI is prone to multiple cross-site scripting
vulnerabilities because it fails to properly sanitize user-supplied
input before using it in dynamically generated content.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This can allow the attacker to steal cookie-based authentication
credentials and launch other attacks.");

  script_tag(name:"affected", value:"Infoblox NetMRI versions 6.2.1, 6.1.2, and 6.0.2.42 are vulnerable,
other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

include("version_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(vers =  get_app_version(cpe:CPE, port:port)) {

  if(version_is_equal(version: vers, test_version: "6.2.1") ||
     version_is_equal(version: vers, test_version: "6.1.2") ||
     version_is_equal(version: vers, test_version: "6.0.2.42")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
