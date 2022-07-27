##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sit_id_param_xss_vuln.nasl 11591 2018-09-25 08:09:20Z asteins $
#
# Support Incident Tracker SiT! 'id' Parameter XSS Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802860");
  script_version("$Revision: 11591 $");
  script_cve_id("CVE-2012-2235");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 10:09:20 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-06-01 11:39:08 +0530 (Fri, 01 Jun 2012)");
  script_name("Support Incident Tracker SiT! 'id' Parameter XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("support_incident_tracker_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sit/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75907");
  script_xref(name:"URL", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2012-012.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"Support Incident Tracker version 3.65 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied input
  to the 'id' parameter in 'index.php', which allows attackers to execute arbitrary HTML and script
  code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Support Incident Tracker and is prone to
  cross site scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

CPE = 'cpe:/a:sitracker:support_incident_tracker';

if(!sitPort = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:sitPort))
  exit(0);

url = dir + '/index.php?id=<script>alert(document.cookie)</script>';
if(http_vuln_check(port: sitPort, url: url, check_header: TRUE,
                   pattern: "<script>alert\(document.cookie\)</script>",
                   extra_check: "Support Incident Tracker")){
  report = report_vuln_url(port:sitPort, url:url);
  security_message(port:sitPort, data:report);
  exit(0);
}

exit(99);
