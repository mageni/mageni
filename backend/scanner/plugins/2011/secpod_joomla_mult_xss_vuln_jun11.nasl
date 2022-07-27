##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_mult_xss_vuln_jun11.nasl 11552 2018-09-22 13:45:08Z cfischer $
#
# Joomla! CMS Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902390");
  script_version("$Revision: 11552 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 15:45:08 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_bugtraq_id(48471, 48475);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! CMS Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45094");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Jun/519");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary script code in
the browser of an unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"Joomla CMS version 1.6.3 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via the
'Itemid' and 'filter_order' parameters in 'index.php', before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to Joomla CMS 1.6.4 or later.");

  script_tag(name:"summary", value:"This host is running Joomla and is prone to multiple cross site scripting
vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/index.php?option=com_contact&view=category&catid=26&id=36&Itemid=-1";><script>alert(/XSS-Test' +
      'ing/)</script>';

if (http_vuln_check(port: port, url: url, pattern: ';><script>alert(/XSS-Testing/)</script>',
                    check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
