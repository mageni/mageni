###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_zimbcomment_mult_vuln.nasl 11960 2018-10-18 10:48:11Z jschulte $
#
# ZiMB Comment Joomla! Component 'controller' Parameter Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804022");
  script_version("$Revision: 11960 $");
  script_cve_id("CVE-2010-1602");
  script_bugtraq_id(39548);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:48:11 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-30 20:15:21 +0530 (Mon, 30 Sep 2013)");

  script_name("ZiMB Comment Joomla! Component 'controller' Parameter Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with ZiMB Comment Joomla! Component and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to disclose
  information or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Input passed via the 'controller' parameter is not properly sanitised before
  being used in the code.");

  script_tag(name:"affected", value:"Joomla Component ZiMB Comment version 0.8.1, Other versions may also be
  affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to disclose the contents
  of any file on the system accessible by the web server.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.iedb.ir/exploits-611.html");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12283");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/88626");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if (!http_port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = dir + "/index.php?option=com_zimbcomment&controller=../../../../../../../../../../" + file + "%00";

  ## Extra check is not possible
  if (http_vuln_check(port:http_port, url:url, check_header:TRUE,
                      pattern:"<b>Fatal error</b>:  require_once\(\): Failed opening required .*" +
                              "/com_zimbcomment/zimbcomment.php")) {
    report = report_vuln_url(port: http_port, url: url);
    security_message(port:http_port, data:report);
    exit(0);
  }
}

exit(99);
