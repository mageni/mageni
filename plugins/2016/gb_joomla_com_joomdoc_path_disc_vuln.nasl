###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla Joomdoc Extension Path Disclosure Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808230");
  script_version("2019-05-16T08:02:32+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-16 08:02:32 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2016-06-20 16:50:11 +0530 (Mon, 20 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("Joomla Joomdoc Extension Path Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Joomla extension
  Joomdoc and is prone to path disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to obtain sensitive information or not.");

  script_tag(name:"insight", value:"The flaw is due to an error in joomla joomdoc
  extension configuration which displays the full path of the file in the error
  message in case of denial of access.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information about the application.");

  script_tag(name:"affected", value:"Joomla Joomdoc component version 4.0.3");

  script_tag(name:"solution", value:"Update to version 4.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.artio.net/joomdoc/joomdoc-changelog");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137381");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://extensions.joomla.org/extension/joomdoc");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_joomdoc&view=documents&path=%27Application%20Forms&Itemid=62";

if(http_vuln_check(port:http_port, url:url,
                   pattern:"<title>Error: 403 JERROR_ALERTNOAUTHOR.*documents.*Application Forms.*</title>",
                   extra_check:">An error has occurred while processing your request.<")) {
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);
