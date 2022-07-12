###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mahara_xss_n_csrf_vuln.nasl 12061 2018-10-24 13:20:52Z asteins $
#
# Mahara Cross Site Scripting and Cross Site Request Forgery Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901199");
  script_version("$Revision: 12061 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 15:20:52 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_bugtraq_id(47033);
  script_cve_id("CVE-2011-0439", "CVE-2011-0440");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Mahara Cross Site Scripting and Cross Site Request Forgery Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43858");
  script_xref(name:"URL", value:"http://mahara.org/interaction/forum/topic.php?id=3205");
  script_xref(name:"URL", value:"http://mahara.org/interaction/forum/topic.php?id=3206");
  script_xref(name:"URL", value:"http://mahara.org/interaction/forum/topic.php?id=3208");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
  script_mandatory_keys("mahara/detected");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site.");
  script_tag(name:"affected", value:"Mahara versions 1.2.x before 1.2.7 and 1.3.x before 1.3.4");
  script_tag(name:"insight", value:"- The application allows users to perform certain actions via HTTP requests
    without performing any validity checks to verify the requests. This can
    be exploited to delete blog posts by tricking a logged in administrative
    user into visiting a malicious web site.

  - Certain input passed via Pieform select box options is not properly
    sanitised before being displayed to the user. This can be exploited to
    insert arbitrary HTML and script code.");
  script_tag(name:"solution", value:"Upgrade to Mahara version 1.2.7 or 1.3.4.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running Mahara and is prone to cross site scripting
  and cross site request forgery vulnerabilities.");
  exit(0);
}

CPE = "cpe:/a:mahara:mahara";

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE)) exit(0);
if (!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_in_range(version:vers, test_version:"1.3.0", test_version2:"1.3.3")) {
  report = report_fixed_ver(installed_version:vers,  fixed_version:"1.3.4");
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.2.0", test_version2:"1.2.6")) {
  report = report_fixed_ver(installed_version:vers,  fixed_version:"1.2.7");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
