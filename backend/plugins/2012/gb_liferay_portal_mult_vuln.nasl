##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_liferay_portal_mult_vuln.nasl 11429 2018-09-17 10:08:59Z cfischer $
#
# Liferay Portal Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802630");
  script_version("$Revision: 11429 $");
  script_bugtraq_id(53546);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 12:08:59 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-05-21 12:12:12 +0530 (Mon, 21 May 2012)");
  script_name("Liferay Portal Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49205");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/May/79");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75654");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522726");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112737/liferay6-xss.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary script code in the browser of an unsuspecting user in the context of
the affected site, steal cookie based authentication credentials, disclose or
modify sensitive information, perform unauthorized actions in the context
of a user's session.");
  script_tag(name:"affected", value:"Liferay Portal version 6.1.10 and prior");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Input passed to the 'uploadProgressId' parameter in html/portal/upload_
progress_poller.jsp is not properly sanitised before being returned to
the user.

  - Input passed to the 'ckEditorConfigFileName' parameter when editing
articles in a journal is not properly sanitised before being returned to
the user.

  - Input passed to the '_16_chartId' parameter when viewing the currency
converter is not properly sanitised before being returned to the user.

  - Input passed to the 'tag' parameter when viewing blog categories is not
properly sanitised before being returned to the user.

  - The application allows users to perform certain actions via HTTP requests
without performing any validity checks to verify the requests. This can be
exploited to disclose potentially sensitive information.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Liferay Portal and is prone to multiple
vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

url = "/c/portal/license";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"Powered by <a [^>]+>Liferay</a>"))
{
  url = "/html/portal/upload_progress_poller.jsp?uploadProgressId=a=1;" +
        "alert(document.cookie);//";

  if(http_vuln_check(port:port, url:url, check_header: TRUE,
     pattern:"parent.a=1;alert\(document.cookie\);//")){
    security_message(port:port);
    exit(0);
  }
}

exit(99);
