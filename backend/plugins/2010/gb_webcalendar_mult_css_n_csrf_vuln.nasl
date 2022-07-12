###############################################################################
# OpenVAS Vulnerability Test
#
# WebCalendar Multiple CSS and CSRF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800472");
  script_version("2019-05-17T12:32:34+0000");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0636", "CVE-2010-0637", "CVE-2010-0638");
  script_bugtraq_id(38053);
  script_name("WebCalendar Multiple CSS and CSRF Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38222");
  script_xref(name:"URL", value:"http://holisticinfosec.org/content/view/133/45/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("webcalendar_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webcalendar/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to conduct cross-site scripting
  and request forgery attacks.");

  script_tag(name:"affected", value:"WebCalendar version 1.2.0 and prior.");

  script_tag(name:"insight", value:"- Input passed to the 'tab' parameter in 'users.php' is not properly
  sanitised before being returned to the user.

  - Input appended to the URL after 'day.php', 'month.php', and 'week.php'
  is not properly sanitised before being returned to the user.

  - The application allows users to perform certain actions via HTTP requests
  without performing any validity checks to verify the requests. This can be
  exploited to delete an event, ban an IP address from posting, or change the
  administrative password if a logged-in administrative user visits a malicious web site.");

  script_tag(name:"solution", value:"Upgrade to WebCalendar version 1.2.1 or later.");

  script_tag(name:"summary", value:"The host is running WebCalendar and is prone to multiple CSS and
  CSRF Vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

wcport = get_http_port(default:80);

wcver = get_kb_item("www/" + wcport + "/webcalendar");
if(isnull(wcver)){
  exit(0);
}

wcver = eregmatch(pattern:"^(.+) under (/.*)$", string:wcver);
if(!isnull(wcver[1]))
{
  if(version_is_less_equal(version:wcver[1], test_version:"1.2.0")){
    security_message(wcport);
  }
}
