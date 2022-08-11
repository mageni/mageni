###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_synology_photo_station_rce_xss_05_15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Synology Photo Station Command Injection and multiple Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:synology:synology_photo_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105280");
  script_cve_id("CVE-2015-4656");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Synology Photo Station Command Injection and multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securify.nl/advisory/SFY20150504/synology_photo_station_multiple_cross_site_scripting_vulnerabilities.html");
  script_xref(name:"URL", value:"https://www.securify.nl/advisory/SFY20150502/command_injection_vulnerability_in_synology_photo_station.html");

  script_tag(name:"insight", value:"Multiple errors exists due to insufficient
 validation of input passed via 'success' parameter to login.php script, 't'
 parameter to /photo/index.php script and 'description' POST parameter to
 photo.php script.");

  script_tag(name:"impact", value:"An attacker may leverage the XSS issues to
execute arbitrary script code in the browser of an unsuspecting user in the context
of the affectedasite. This may allow the attacker to steal cookie-based
authentication credentials and launch other attacks.

The Command Injection vulnerability allows an attacker to execute arbitrary commands
with the privileges of the webserver. An attacker can use this vulnerability to
compromise a Synology DiskStation NAS, including all data stored on the NAS.");

  script_tag(name:"vuldetect", value:"Send a crafted http GET request and check if it
is possible to read cookie or not.");
  script_tag(name:"solution", value:"Update to 6.3-2945 or newer.");
  script_tag(name:"summary", value:"Synology Photo Station is prone to a command
injection vulnerability and multiple cross-site scripting vulnerabilities
because it fails to sanitize user-supplied input.");

  script_tag(name:"affected", value:"Photo Station 6 < 6.3-2945");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-26 14:30:57 +0200 (Tue, 26 May 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_synology_photo_station_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("synology_photo_station/installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!photoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:photoPort)){
  exit(0);
}

url = dir + "/m/login.php?success=%3E%3Cscript%3Ealert%28documen" +
            "t.cookie%29%3C/script%3E";

if(http_vuln_check(port:photoPort, url:url, pattern:"<script>alert\(document.cookie\)</script>",
   extra_check: make_list(">Photo Station<", ">Synology"), check_header:TRUE))
{
  report = report_vuln_url( port:photoPort, url:url );
  security_message(port:photoPort, data:report);
  exit(0);
}

exit(99);